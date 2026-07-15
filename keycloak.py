"""h2c operator: keycloak — Keycloak, KeycloakRealmImport.

Converts Keycloak operator CRDs into compose services.

- Keycloak CR → compose service (image, KC_* env, ports, command)
- KeycloakRealmImport CR → realm JSON files mounted for auto-import

Cache is forced to local (compose = single instance, no Infinispan clustering).
ACME/TLS is left to Caddy. The K8s operator Deployment itself is ignored (K8s-only).
"""

import base64
import json
import os
import secrets
import string
import sys

from dekube import ProviderResult, Provider, apply_replacements  # pylint: disable=import-error  # h2c resolves at runtime


# ---- converter class -------------------------------------------------------

class KeycloakProvider(Provider):  # pylint: disable=too-few-public-methods  # contract: one class, one method
    """Convert Keycloak and KeycloakRealmImport CRDs to compose services.

    KeycloakRealmImport is indexed first (kinds list order = call order),
    then Keycloak processes them and produces compose services.
    """

    name = "keycloak"
    kinds = ["KeycloakRealmImport", "Keycloak"]
    priority = 500  # after cert-manager/trust-manager if present (uses their output when available)

    def __init__(self):
        self._realm_imports = {}   # keycloakCRName → [manifest]

    def convert(self, kind, manifests, ctx):
        """Dispatch to realm import indexer or Keycloak processor."""
        if kind == "KeycloakRealmImport":
            self._index_realm_imports(manifests)
            return ProviderResult()
        return self._process_keycloak(manifests, ctx)

    def _index_realm_imports(self, manifests):
        for m in manifests:
            cr_name = (m.get("spec") or {}).get("keycloakCRName", "")
            self._realm_imports.setdefault(cr_name, []).append(m)

    def _process_keycloak(self, manifests, ctx):
        services = {}
        for m in manifests:
            name = (m.get("metadata") or {}).get("name", "?")
            spec = m.get("spec") or {}

            env = self._build_env(spec, ctx, name)
            service = {
                "restart": "always",
                "image": spec.get("image", "quay.io/keycloak/keycloak:latest"),
                "environment": env,
            }

            # TLS secret for HTTPS listener
            tls_secret = (spec.get("http") or {}).get("tlsSecret")
            if tls_secret and tls_secret in ctx.generated_secrets:
                vols = service.setdefault("volumes", [])
                vols.append(f"./secrets/{tls_secret}/tls.crt"
                            f":/opt/keycloak/conf/server.crt.pem:ro")
                vols.append(f"./secrets/{tls_secret}/tls.key"
                            f":/opt/keycloak/conf/server.key.pem:ro")
                env["KC_HTTPS_CERTIFICATE_FILE"] = \
                    "/opt/keycloak/conf/server.crt.pem"
                env["KC_HTTPS_CERTIFICATE_KEY_FILE"] = \
                    "/opt/keycloak/conf/server.key.pem"

            # Volumes from podTemplate (e.g. CA trust bundle)
            pod_vols = self._build_pod_template_volumes(spec, ctx)
            if pod_vols:
                service.setdefault("volumes", []).extend(pod_vols)

            # Command
            cmd = ["start"]

            # Realm imports → JSON files + --import-realm
            realm_imports = self._realm_imports.get(name, [])
            if realm_imports:
                realm_dir = self._write_realm_files(
                    name, realm_imports, ctx)
                service.setdefault("volumes", []).append(
                    f"./{realm_dir}:/opt/keycloak/data/import:ro")
                cmd.append("--import-realm")

            service["command"] = cmd

            services[name] = service

            # Register in services_by_selector so later operators (e.g.
            # servicemonitor) can discover this service by label matching.
            # In K8s the Keycloak Operator creates the Service at runtime;
            # here we replicate what it would look like.
            svc_ports = self._build_service_ports(env, bool(tls_secret))
            ns = (m.get("metadata") or {}).get("namespace", "")
            ctx.services_by_selector[name] = {
                "name": name,
                "namespace": ns,
                "selector": {
                    "app.kubernetes.io/instance": name,
                },
                "type": "ClusterIP",
                "ports": svc_ports,
            }

            # The K8s Keycloak Operator creates a Service named
            # "<cr-name>-service" at runtime. Register it in both
            # alias_map and services_by_selector so _build_network_aliases
            # generates FQDN aliases for it on the compose service.
            k8s_svc_name = f"{name}-service"
            ctx.alias_map[k8s_svc_name] = name
            ctx.services_by_selector[k8s_svc_name] = {
                "name": k8s_svc_name,
                "namespace": ns,
                "selector": {"app.kubernetes.io/instance": name},
                "type": "ClusterIP",
                "ports": svc_ports,
            }

            print(f"  keycloak: generated service '{name}'",
                  file=sys.stderr)

        return ProviderResult(services=services)

    def _write_realm_files(self, kc_name, realm_imports, ctx):
        """Write realm JSON files for auto-import on startup."""
        safe_name = os.path.basename(kc_name)
        realm_dir = os.path.join("configmaps", f"{safe_name}-realms")
        abs_dir = os.path.join(ctx.output_dir, realm_dir)
        os.makedirs(abs_dir, exist_ok=True)
        out_real = os.path.realpath(ctx.output_dir) + os.sep

        for m in realm_imports:
            spec = m.get("spec") or {}
            realm = spec.get("realm") or {}
            realm_name = os.path.basename(realm.get("realm", "unknown"))

            # Skip master realm: let Keycloak create it with defaults.
            # In K8s the operator imports realms AFTER startup (separate
            # Jobs, IGNORE_EXISTING) so the default master is preserved.
            # With --import-realm our minimal JSON would replace the
            # default user-profile config, breaking the bootstrap admin.
            if realm_name == "master":
                print("  keycloak: skipping master realm import "
                      "(preserving defaults)", file=sys.stderr)
                continue

            # Resolve ${PLACEHOLDER} from secrets
            placeholders = spec.get("placeholders") or {}
            if placeholders:
                realm = self._resolve_placeholders(realm, placeholders, ctx)

            # Rewrite K8s DNS and apply replacements
            realm = self._rewrite_realm_urls(realm, ctx.replacements)

            filepath = os.path.join(abs_dir, f"{realm_name}-realm.json")
            if not os.path.realpath(filepath).startswith(out_real):
                continue
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(realm, f, indent=2, ensure_ascii=False)

            print(f"  keycloak: wrote realm '{realm_name}'",
                  file=sys.stderr)

        return realm_dir

    # ---- helpers ---------------------------------------------------------------

    @staticmethod
    def _secret_val(ctx, name, key):
        """Resolve a single key from a K8s Secret in ctx.secrets."""
        sec = ctx.secrets.get(name, {})
        val = (sec.get("stringData") or {}).get(key)
        if val is not None:
            return val
        raw = (sec.get("data") or {}).get(key)
        if raw is not None:
            try:
                return base64.b64decode(raw).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return raw
        return None

    @staticmethod
    def _secret_ref(ref, ctx):
        """Resolve a Keycloak-style secret ref: {name: ..., key: ...}."""
        return KeycloakProvider._secret_val(ctx, ref.get("name", ""), ref.get("key", ""))

    @staticmethod
    def _write_data_files(name, category, data, output_dir, generated):
        """Write data entries as files under category/name/. Returns relative dir."""
        rel_dir = os.path.join(category, name)
        if name not in generated:
            generated.add(name)
            abs_dir = os.path.join(output_dir, rel_dir)
            os.makedirs(abs_dir, exist_ok=True)
            out_real = os.path.realpath(output_dir) + os.sep
            for key, value in data.items():
                file_path = os.path.join(abs_dir, key)
                if not os.path.realpath(file_path).startswith(out_real):
                    continue
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(str(value))
        return rel_dir

    @staticmethod
    def _decode_secret_data(sec):
        """Merge stringData and base64-decoded data from a K8s Secret."""
        result = {}
        for k, v in (sec.get("stringData") or {}).items():
            result[k] = v
        for k, v in (sec.get("data") or {}).items():
            if k not in result:
                try:
                    result[k] = base64.b64decode(v).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    result[k] = v
        return result

    @staticmethod
    def _build_volume_source_map(volumes):
        """Map volume names to their source type (configmap or secret)."""
        vol_map = {}
        for v in volumes:
            if not v:
                continue
            vname = v.get("name", "")
            if "configMap" in v:
                vol_map[vname] = {
                    "type": "configmap",
                    "name": v["configMap"].get("name", ""),
                }
            elif "secret" in v:
                vol_map[vname] = {
                    "type": "secret",
                    "name": v["secret"].get("secretName", ""),
                }
        return vol_map

    @staticmethod
    def _build_pod_template_volumes(spec, ctx):
        """Process volume mounts from unsupported.podTemplate.spec."""
        pod_spec = ((spec.get("unsupported") or {})
                    .get("podTemplate") or {}).get("spec") or {}

        volumes = pod_spec.get("volumes") or []
        if not volumes:
            return []

        # Find keycloak container's volumeMounts
        mounts = []
        for container in (pod_spec.get("containers") or []):
            if not container:
                continue
            if container.get("name") == "keycloak":
                mounts = container.get("volumeMounts") or []
                break
        if not mounts:
            return []

        vol_map = KeycloakProvider._build_volume_source_map(volumes)

        result = []
        for vm in mounts:
            if not vm:
                continue
            source = vol_map.get(vm.get("name", ""))
            if source is None:
                continue

            mount_path = vm.get("mountPath", "")
            sub_path = vm.get("subPath")
            ro = ":ro" if vm.get("readOnly", False) else ""

            if source["type"] == "configmap":
                rel_dir = KeycloakProvider._mount_configmap(source["name"], ctx)
            elif source["type"] == "secret":
                rel_dir = KeycloakProvider._mount_secret(source["name"], ctx)
            else:
                continue

            if rel_dir is None:
                continue
            if sub_path:
                result.append(f"./{rel_dir}/{sub_path}:{mount_path}{ro}")
            else:
                result.append(f"./{rel_dir}:{mount_path}{ro}")

        return result

    @staticmethod
    def _mount_configmap(cm_name, ctx):
        """Generate configmap files, return relative dir or None."""
        cm = ctx.configmaps.get(cm_name)
        if cm is None:
            ctx.warnings.append(
                f"Keycloak podTemplate: ConfigMap '{cm_name}' not found")
            return None
        return KeycloakProvider._write_data_files(
            cm_name, "configmaps", cm.get("data") or {},
            ctx.output_dir, ctx.generated_cms)

    @staticmethod
    def _mount_secret(sec_name, ctx):
        """Generate secret files, return relative dir or None."""
        sec = ctx.secrets.get(sec_name)
        if sec is None:
            ctx.warnings.append(
                f"Keycloak podTemplate: Secret '{sec_name}' not found")
            return None
        return KeycloakProvider._write_data_files(
            sec_name, "secrets", KeycloakProvider._decode_secret_data(sec),
            ctx.output_dir, ctx.generated_secrets)

    @staticmethod
    def _rewrite_realm_urls(obj, replacements):
        """Apply replacements in all string values."""
        if isinstance(obj, str):
            if replacements:
                return apply_replacements(obj, replacements)
            return obj
        if isinstance(obj, dict):
            return {k: KeycloakProvider._rewrite_realm_urls(v, replacements) for k, v in obj.items()}
        if isinstance(obj, list):
            return [KeycloakProvider._rewrite_realm_urls(item, replacements) for item in obj]
        return obj

    @staticmethod
    def _generate_password(length=24):
        """Generate a random password (alphanumeric, no shell-hostile chars)."""
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def _ensure_initial_admin(kc_name, output_dir, generated_secrets):
        """Generate or reuse initial-admin credentials, written as a K8s-style Secret."""
        safe_name = os.path.basename(kc_name)
        secret_name = f"{safe_name}-initial-admin"
        secret_dir = os.path.join(output_dir, "secrets", secret_name)

        username_file = os.path.join(secret_dir, "username")
        password_file = os.path.join(secret_dir, "password")

        # Reuse existing credentials (idempotent across runs)
        if os.path.isfile(username_file) and os.path.isfile(password_file):
            with open(username_file, encoding="utf-8") as f:
                username = f.read().strip()
            with open(password_file, encoding="utf-8") as f:
                password = f.read().strip()
            print(f"  keycloak: reusing admin credentials from secrets/{secret_name}/",
                  file=sys.stderr)
        else:
            username = "temp-admin"
            password = KeycloakProvider._generate_password()
            os.makedirs(secret_dir, exist_ok=True)
            with open(username_file, "w", encoding="utf-8") as f:
                f.write(username)
            with open(password_file, "w", encoding="utf-8") as f:
                f.write(password)
            print(f"  keycloak: generated admin credentials → secrets/{secret_name}/",
                  file=sys.stderr)

        generated_secrets.add(secret_name)
        return {"username": username, "password": password}

    @staticmethod
    def _resolve_placeholders(realm, placeholders, ctx):
        """Replace ${PLACEHOLDER} in realm dict values with secret data."""
        resolved = {}
        for ph_name, ph_spec in placeholders.items():
            secret = ph_spec.get("secret")
            if secret:
                val = KeycloakProvider._secret_ref(secret, ctx)
                if val:
                    resolved[ph_name] = val

        if not resolved:
            return realm

        def _walk(obj):
            if isinstance(obj, str):
                for ph, val in resolved.items():
                    obj = obj.replace(f"${{{ph}}}", val)
                return obj
            if isinstance(obj, dict):
                return {k: _walk(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [_walk(item) for item in obj]
            return obj

        return _walk(realm)

    # ---- env var mapping -------------------------------------------------------

    @staticmethod
    def _build_db_env(db, ctx):
        """Map spec.db → KC_DB_* env vars."""
        env = {}
        if db.get("vendor"):
            env["KC_DB"] = db["vendor"]
        if db.get("url"):
            env["KC_DB_URL"] = db["url"]
        else:
            if db.get("host"):
                env["KC_DB_URL_HOST"] = db["host"]
            if db.get("port"):
                env["KC_DB_URL_PORT"] = str(db["port"])
            if db.get("database"):
                env["KC_DB_URL_DATABASE"] = db["database"]
        if db.get("schema"):
            env["KC_DB_SCHEMA"] = db["schema"]
        for field, env_key in [("usernameSecret", "KC_DB_USERNAME"),
                               ("passwordSecret", "KC_DB_PASSWORD")]:
            ref = db.get(field)
            if ref:
                val = KeycloakProvider._secret_ref(ref, ctx)
                if val:
                    env[env_key] = val
        return env

    @staticmethod
    def _build_http_env(spec):
        """Map spec.http, httpManagement, hostname, proxy → KC_* env vars."""
        env = {}
        http = spec.get("http") or {}
        if "httpEnabled" in http:
            env["KC_HTTP_ENABLED"] = str(http["httpEnabled"]).lower()
        if http.get("httpPort"):
            env["KC_HTTP_PORT"] = str(http["httpPort"])
        if http.get("httpsPort"):
            env["KC_HTTPS_PORT"] = str(http["httpsPort"])
        # The K8s Keycloak Operator always enables the management interface
        # (default port 9000). The CR may override it via httpManagement.port.
        mgmt_port = (spec.get("httpManagement") or {}).get("port", 9000)
        env["KC_HTTP_MANAGEMENT_PORT"] = str(mgmt_port)

        hostname = spec.get("hostname") or {}
        if hostname.get("hostname"):
            env["KC_HOSTNAME"] = hostname["hostname"]
        if hostname.get("admin"):
            env["KC_HOSTNAME_ADMIN"] = hostname["admin"]
        if "backchannelDynamic" in hostname:
            env["KC_HOSTNAME_BACKCHANNEL_DYNAMIC"] = str(
                hostname["backchannelDynamic"]).lower()
        if "strict" in hostname:
            env["KC_HOSTNAME_STRICT"] = str(hostname["strict"]).lower()

        proxy = spec.get("proxy") or {}
        if proxy.get("headers"):
            env["KC_PROXY_HEADERS"] = proxy["headers"]
        return env

    @staticmethod
    def _build_options_env(spec, ctx, kc_name="keycloak"):
        """Map features, additionalOptions, podTemplate env, bootstrap admin."""
        env = {}
        features = spec.get("features") or {}
        enabled = features.get("enabled")
        if enabled:
            env["KC_FEATURES"] = ",".join(enabled)
        disabled = features.get("disabled")
        if disabled:
            env["KC_FEATURES_DISABLED"] = ",".join(disabled)

        for opt in spec.get("additionalOptions") or []:
            if not opt:
                continue
            env_name = "KC_" + opt["name"].upper().replace("-", "_")
            if "value" in opt:
                env[env_name] = opt["value"]
            elif "secret" in opt:
                val = KeycloakProvider._secret_ref(opt["secret"], ctx)
                if val:
                    env[env_name] = val

        pod_spec = ((spec.get("unsupported") or {})
                    .get("podTemplate") or {}).get("spec") or {}
        for container in pod_spec.get("containers") or []:
            if not container:
                continue
            if container.get("name") == "keycloak":
                for e in container.get("env") or []:
                    if not e:
                        continue
                    if "value" in e:
                        env[e["name"]] = e["value"]

        env.update(KeycloakProvider._resolve_bootstrap_admin(spec, ctx, kc_name))
        return env

    @staticmethod
    def _resolve_bootstrap_admin(spec, ctx, kc_name):
        """Resolve bootstrap admin credentials from CRD or generate them."""
        admin_secret = ((spec.get("bootstrapAdmin") or {})
                        .get("user") or {}).get("secret")
        if admin_secret:
            env = {}
            for field, env_key in [("username", "KC_BOOTSTRAP_ADMIN_USERNAME"),
                                   ("password", "KC_BOOTSTRAP_ADMIN_PASSWORD")]:
                val = KeycloakProvider._secret_val(ctx, admin_secret, field)
                if val:
                    env[env_key] = val
            return env
        # No bootstrapAdmin in CRD — K8s operator creates it dynamically.
        # Replicate: generate credentials, write to secrets/ like a K8s Secret.
        creds = KeycloakProvider._ensure_initial_admin(
            kc_name, ctx.output_dir, ctx.generated_secrets)
        return {
            "KC_BOOTSTRAP_ADMIN_USERNAME": creds["username"],
            "KC_BOOTSTRAP_ADMIN_PASSWORD": creds["password"],
        }

    @staticmethod
    def _build_env(spec, ctx, kc_name="keycloak"):
        """Map a Keycloak CR spec to KC_* environment variables."""
        env = {}
        env.update(KeycloakProvider._build_db_env(spec.get("db") or {}, ctx))
        env.update(KeycloakProvider._build_http_env(spec))
        env["KC_CACHE"] = "local"  # compose = single instance, no clustering
        # The K8s Keycloak Operator enables these implicitly; Keycloak needs
        # them to activate the management interface (separate port for metrics).
        env.setdefault("KC_HEALTH_ENABLED", "true")
        env.setdefault("KC_METRICS_ENABLED", "true")
        env.update(KeycloakProvider._build_options_env(spec, ctx, kc_name))
        return env

    @staticmethod
    def _build_service_ports(env, tls_enabled):
        """Build K8s-style Service port list from Keycloak env vars."""
        svc_ports = []
        if tls_enabled:
            https_port = int(env.get("KC_HTTPS_PORT", 8443))
            svc_ports.append({"name": "https", "port": https_port,
                              "targetPort": https_port})
        http_enabled = env.get("KC_HTTP_ENABLED", "false") == "true"
        if http_enabled or not tls_enabled:
            http_port = int(env.get("KC_HTTP_PORT", 8080))
            svc_ports.append({"name": "http", "port": http_port,
                              "targetPort": http_port})
        if "KC_HTTP_MANAGEMENT_PORT" in env:
            mgmt_port = int(env["KC_HTTP_MANAGEMENT_PORT"])
            svc_ports.append({"name": "management", "port": mgmt_port,
                              "targetPort": mgmt_port})
        else:
            # No dedicated management port — metrics served on main listener.
            # Map "management" to the main port so ServiceMonitors referencing
            # port "management" resolve.
            main_port = (int(env.get("KC_HTTPS_PORT", 8443)) if tls_enabled
                         else int(env.get("KC_HTTP_PORT", 8080)))
            svc_ports.append({"name": "management", "port": main_port,
                              "targetPort": main_port})
        return svc_ports

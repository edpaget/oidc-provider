(ns oidc-provider.resource-metadata
  "OAuth 2.0 Protected Resource Metadata per RFC 9728.

   Generates the JSON document served at `/.well-known/oauth-protected-resource`
   that describes a resource server's authorization requirements. This tells clients
   which authorization servers to use, what scopes are available, and how to present
   bearer tokens."
  (:require
   [malli.core :as m]))

(set! *warn-on-reflection* true)

(def ResourceServerConfig
  "Malli schema for protected resource metadata configuration."
  [:map
   [:resource :string]
   [:authorization-servers [:vector :string]]
   [:scopes-supported {:optional true} [:vector :string]]
   [:bearer-methods-supported {:optional true} [:vector :string]]
   [:resource-documentation {:optional true} :string]])

(defn resource-metadata
  "Generates OAuth 2.0 Protected Resource Metadata per RFC 9728.

   Takes a configuration map matching [[ResourceServerConfig]] containing the resource
   identifier, authorization server URIs, and optional metadata. Validates the input
   and builds the metadata document with snake_case keys suitable for JSON serialization.
   Defaults `bearer_methods_supported` to `[\"header\"]` when not provided."
  [{:keys [resource
           authorization-servers
           scopes-supported
           bearer-methods-supported
           resource-documentation]  :as config}]
  {:pre [(m/validate ResourceServerConfig config)]}
  (cond-> {:resource                 resource
           :authorization_servers    authorization-servers
           :bearer_methods_supported (or bearer-methods-supported ["header"])}
    scopes-supported (assoc :scopes_supported scopes-supported)
    resource-documentation (assoc :resource_documentation resource-documentation)))

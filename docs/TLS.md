# TLS and expected certificates

This document lists all required and optional TLS certificates for NetObserv. You can also refer to the [Helm chart templates](../helm/templates/certificates.yaml) for cert-manager.

## Required certificates

Those certificates are always required and are not configurable:

<table>
  <thead>
    <tr>
      <th>Service name</th>
      <th>Resource kind</th>
      <th>Resource name</th>
      <th>Resource keys</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>netobserv-webhook-service</td>
      <td>Secret</td>
      <td>webhook-server-cert</td>
      <td>tls.crt, tls.key</td>
    </tr>
    <tr>
      <td>netobserv-metrics-service</td>
      <td>Secret</td>
      <td>manager-metrics-tls</td>
      <td>tls.crt, tls.key</td>
    </tr>
  </tbody>
</table>

## Agent to FLP certificates

When `spec.deploymentModel` is "Service", the traffic from eBPF agents to flowlogs-pipeline pods uses TLS by default. It is possible to disable TLS, though not recommended in production-grade environments, as it decreases the security of the NetObserv deployments.

In "Kafka" mode, the TLS/SASL configuration depends on your installation. The Kafka clients used in NetObserv support simple TLS, mTLS, SASL as well as no TLS. We recommend the use of mTLS for higher security standards.

In "Direct" mode, the traffic doesn't leave the host and is not encrypted.

The tables below apply to the "Service" mode.

### Auto (TLS)

When `spec.processor.service.tlsType` is "Auto":

<table>
  <thead>
    <tr>
      <th>Needed by</th>
      <th>Resource kind</th>
      <th>Resource name</th>
      <th>Resource keys</th>
      <th>Notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>flowlogs-pipeline</td>
      <td>Secret</td>
      <td>flowlogs-pipeline-cert</td>
      <td>tls.crt, tls.key</td>
      <td></td>
    </tr>
    <tr>
      <td>eBPF Agents</td>
      <td>ConfigMap</td>
      <td>netobserv-ca</td>
      <td>service-ca.crt</td>
      <td>Must be installed in netobserv-privileged namespace.</td>
    </tr>
  </tbody>
</table>

### Auto (mTLS)

When `spec.processor.service.tlsType` is "Auto-mTLS":

<table>
  <thead>
    <tr>
      <th>Needed by</th>
      <th>Resource kind</th>
      <th>Resource name</th>
      <th>Resource keys</th>
      <th>Notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>flowlogs-pipeline</td>
      <td>Secret</td>
      <td>flowlogs-pipeline-cert</td>
      <td>tls.crt, tls.key</td>
      <td></td>
    </tr>
    <tr>
      <td>flowlogs-pipeline</td>
      <td>ConfigMap</td>
      <td>netobserv-ca</td>
      <td>service-ca.crt</td>
      <td></td>
    </tr>
    <tr>
      <td>eBPF Agents</td>
      <td>Secret</td>
      <td>ebpf-agent-cert</td>
      <td>tls.crt, tls.key</td>
      <td>Must be installed in netobserv-privileged namespace.</td>
    </tr>
    <tr>
      <td>eBPF Agents</td>
      <td>ConfigMap</td>
      <td>netobserv-ca</td>
      <td>service-ca.crt</td>
      <td>Must be installed in netobserv-privileged namespace.</td>
    </tr>
  </tbody>
</table>

### Provided

When `spec.processor.service.tlsType` is "Provided", you can specify any Secret or ConfigMap for TLS or mTLS, via `spec.processor.service.providedCertificates`.

For mTLS, configure `spec.processor.service.providedCertificates.clientCert`. For simple TLS, do not set the client cert config.

## Informers to Processor certificates

When `spec.processor.informerCacheProxy.enabled` is `true`, informers communicate with processors via gRPC on port 9402 (k8scache). TLS can be configured for this communication.

### Auto (TLS)

When `spec.processor.informerCacheProxy.tls.type` is "Auto":

<table>
  <thead>
    <tr>
      <th>Needed by</th>
      <th>Resource kind</th>
      <th>Resource name</th>
      <th>Resource keys</th>
      <th>Notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>flowlogs-pipeline</td>
      <td>Secret</td>
      <td>flowlogs-pipeline-k8scache-cert</td>
      <td>tls.crt, tls.key</td>
      <td>Issued for the dedicated k8scache Service.</td>
    </tr>
    <tr>
      <td>flowlogs-pipeline-informers</td>
      <td>ConfigMap</td>
      <td>openshift-service-ca.crt</td>
      <td>service-ca.crt</td>
      <td></td>
    </tr>
  </tbody>
</table>

### Auto (mTLS)

When `spec.processor.informerCacheProxy.tls.type` is "Auto-mTLS":

<table>
  <thead>
    <tr>
      <th>Needed by</th>
      <th>Resource kind</th>
      <th>Resource name</th>
      <th>Resource keys</th>
      <th>Notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>flowlogs-pipeline</td>
      <td>Secret</td>
      <td>flowlogs-pipeline-k8scache-cert</td>
      <td>tls.crt, tls.key</td>
      <td>Issued for the dedicated k8scache Service.</td>
    </tr>
    <tr>
      <td>flowlogs-pipeline</td>
      <td>ConfigMap</td>
      <td>netobserv-ca</td>
      <td>service-ca.crt</td>
      <td></td>
    </tr>
    <tr>
      <td>flowlogs-pipeline-informers</td>
      <td>Secret</td>
      <td>flowlogs-pipeline-informers-k8scache-client-cert</td>
      <td>tls.crt, tls.key</td>
      <td></td>
    </tr>
    <tr>
      <td>flowlogs-pipeline-informers</td>
      <td>ConfigMap</td>
      <td>netobserv-ca</td>
      <td>service-ca.crt</td>
      <td></td>
    </tr>
  </tbody>
</table>

### Provided

When `spec.processor.informerCacheProxy.tls.type` is "Provided", you can specify any Secret or ConfigMap for TLS or mTLS, via `spec.processor.informerCacheProxy.tls.providedCertificates`.

For mTLS, configure both `serverCert` and `clientCert`. For simple TLS, only configure `serverCert`.

## Informer metrics

The `flowlogs-pipeline-informers` metrics endpoint listens on port 9091. It uses the same TLS setting as `spec.processor.metrics.server.tls`. With `type: Auto` on OpenShift, the operator creates the `flowlogs-pipeline-informers-metrics` Service and mounts its serving certificate into the informer pods. Prometheus scrapes this endpoint over HTTPS. With `type: Provided`, the supplied certificate must also be valid for `flowlogs-pipeline-informers-metrics.<namespace>.svc`. With `type: Disabled`, the endpoint remains HTTP.

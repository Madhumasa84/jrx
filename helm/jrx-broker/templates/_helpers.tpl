{{/*
Expand the name of the chart.
*/}}
{{- define "jrx-broker.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "jrx-broker.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "jrx-broker.tlsVolume" -}}
{{- $volume := .Values.volumes.tls -}}
{{- $secret := .Values.secrets.tls -}}
{{- $tls := .Values.config.jev.brokerTls -}}
{{- if $volume.existingClaim }}
persistentVolumeClaim:
  claimName: {{ $volume.existingClaim | quote }}
{{- else }}
{{- $prefix := printf "%s/" (trimSuffix "/" $volume.mountPath) }}
secret:
  secretName: {{ required "secrets.tls.existingSecret is required for the TLS Secret volume" $secret.existingSecret | quote }}
  defaultMode: 0440
  items:
    {{- range $item := list (dict "key" $secret.certKey "path" $tls.certPath) (dict "key" $secret.keyKey "path" $tls.keyPath) (dict "key" $secret.caKey "path" $tls.clientCaPath) }}
    {{- $path := clean $item.path }}
    {{- if not (hasPrefix $prefix $path) }}
    {{- fail "TLS Secret file paths must be under volumes.tls.mountPath" }}
    {{- end }}
    - key: {{ $item.key | quote }}
      path: {{ trimPrefix $prefix $path | quote }}
    {{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "jrx-broker.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "jrx-broker.labels" -}}
helm.sh/chart: {{ include "jrx-broker.chart" . }}
{{ include "jrx-broker.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "jrx-broker.selectorLabels" -}}
app.kubernetes.io/name: {{ include "jrx-broker.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "jrx-broker.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "jrx-broker.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

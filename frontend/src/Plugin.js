import React, { useCallback, useEffect, useMemo, useState } from 'react'
import {
  api,
  useAlert,
  timeAgo,
  Page,
  ListHeader,
  Card,
  SectionHeader,
  StatTile,
  StatusDot,
  Toggle,
  TextField,
  ModalConfirm,
  Loading,
  EmptyState,
  Badge,
  BadgeText,
  Box,
  Button,
  ButtonText,
  Heading,
  HStack,
  Input,
  InputField,
  Text,
  Textarea,
  TextareaInput,
  VStack
} from '@spr-networks/plugin-ui'
import LanPresence from './LanPresencePanel'

const PLUGIN_BASE = `/plugins/${api.pluginURI() || 'spr-opencanary'}`

const SERVICES = [
  { key: 'ftp', label: 'FTP', mark: 'FT', protocol: 'TCP', description: 'File server login' },
  { key: 'ssh', label: 'SSH', mark: 'SH', protocol: 'TCP', description: 'Shell login and client fingerprint' },
  { key: 'http', label: 'HTTP', mark: 'HT', protocol: 'TCP', description: 'NAS-style web login' },
  { key: 'https', label: 'HTTPS', mark: 'HS', protocol: 'TCP', description: 'Encrypted web login' },
  { key: 'telnet', label: 'Telnet', mark: 'TN', protocol: 'TCP', description: 'Legacy console login' },
  { key: 'mysql', label: 'MySQL', mark: 'MY', protocol: 'TCP', description: 'Database authentication' },
  { key: 'mssql', label: 'Microsoft SQL', mark: 'MS', protocol: 'TCP', description: 'SQL Server authentication' },
  { key: 'mongodb', label: 'MongoDB', mark: 'MO', protocol: 'TCP', description: 'Database commands and auth' },
  { key: 'redis', label: 'Redis', mark: 'RD', protocol: 'TCP', description: 'Cache commands' },
  { key: 'rdp', label: 'Remote Desktop', mark: 'DP', protocol: 'TCP', description: 'Windows remote access' },
  { key: 'vnc', label: 'VNC', mark: 'VN', protocol: 'TCP', description: 'Desktop login' },
  { key: 'git', label: 'Git', mark: 'GT', protocol: 'TCP', description: 'Repository clone attempts' },
  { key: 'httpproxy', label: 'HTTP proxy', mark: 'PX', protocol: 'TCP', description: 'Proxy authentication' },
  { key: 'snmp', label: 'SNMP', mark: 'SN', protocol: 'UDP', description: 'Management OID requests' },
  { key: 'ntp', label: 'NTP', mark: 'NT', protocol: 'UDP', description: 'Time-service probes' },
  { key: 'sip', label: 'SIP', mark: 'SI', protocol: 'UDP', description: 'VoIP requests' },
  { key: 'tftp', label: 'TFTP', mark: 'TF', protocol: 'UDP', description: 'Firmware file requests' },
  { key: 'tcpbanner', label: 'TCP banner', mark: 'TB', protocol: 'TCP', description: 'Custom service socket' }
]

const PRESETS = {
  nas: ['ftp', 'ssh', 'http', 'https'],
  linux: ['ftp', 'ssh', 'http', 'mysql', 'redis', 'git'],
  windows: ['http', 'https', 'mssql', 'rdp', 'vnc'],
  network: ['http', 'https', 'ssh', 'telnet', 'snmp', 'ntp']
}

const SERVICE_LABELS = Object.fromEntries(SERVICES.map((service) => [service.key, service.label]))

const formFromConfig = (config) => ({
  NodeID: config?.NodeID || 'spr-canary-01',
  IgnoreIPs: (config?.IgnoreIPs || []).join('\n'),
  Services: Object.fromEntries(
    Object.entries(config?.Services || {}).map(([key, service]) => [
      key,
      { Enabled: !!service.Enabled, Port: String(service.Port || '') }
    ])
  ),
  Webhook: {
    Enabled: !!config?.Webhook?.Enabled,
    Kind: config?.Webhook?.Kind || 'generic',
    URL: '',
    Clear: false
  }
})

const parseIgnoreList = (value) =>
  (value || '')
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter(Boolean)

const formatUptime = (seconds) => {
  if (!seconds) return '—'
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`
  return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`
}

const errorText = async (error, fallback) => {
  try {
    if (error?.response) {
      const body = await error.response.json()
      if (body?.Error) return body.Error
    }
  } catch (_) {
    // The API response may already have been consumed; use the friendly fallback.
  }
  return fallback
}

const Label = ({ children }) => (
  <Text
    size="2xs"
    color="$muted500"
    fontWeight="$semibold"
    sx={{ '@base': { letterSpacing: 0.75, textTransform: 'uppercase' } }}
  >
    {children}
  </Text>
)

const Mono = ({ children, ...props }) => (
  <Text
    color="$textLight900"
    sx={{ '@base': { fontFamily: 'monospace' }, _dark: { color: '$textDark50' } }}
    {...props}
  >
    {children}
  </Text>
)

const Segment = ({ options, value, onChange }) => (
  <HStack flexWrap="wrap" gap="$2" flexShrink={1} maxWidth="$full">
    {options.map((option) => (
      <Button
        key={option.value}
        size="xs"
        borderRadius="$full"
        variant={value === option.value ? 'solid' : 'outline'}
        action={value === option.value ? 'primary' : 'secondary'}
        onPress={() => onChange(option.value)}
      >
        <ButtonText>{option.label}</ButtonText>
      </Button>
    ))}
  </HStack>
)

const PulseChart = ({ values = [] }) => {
  const max = Math.max(1, ...values)
  return (
    <HStack h={72} alignItems="flex-end" space="xs" accessibilityLabel="Alerts over the last 24 hours">
      {(values.length ? values : Array(24).fill(0)).map((value, index) => (
        <Box
          key={index}
          flex={1}
          minWidth={3}
          h={`${Math.max(8, Math.round((value / max) * 100))}%`}
          borderRadius="$xs"
          bg={value ? '$primary500' : '$muted200'}
          sx={{ _dark: { bg: value ? '$primary500' : '$muted800' } }}
        />
      ))}
    </HStack>
  )
}

const ProtectionMark = ({ running }) => (
  <Box w={96} h={96} alignItems="center" justifyContent="center" flexShrink={0}>
    <Box
      position="absolute"
      w={96}
      h={96}
      borderRadius="$full"
      borderWidth={1}
      borderColor={running ? '$primary200' : '$muted300'}
      sx={{ _dark: { borderColor: running ? '$primary800' : '$muted700' } }}
    />
    <Box
      position="absolute"
      w={72}
      h={72}
      borderRadius="$full"
      bg={running ? '$primary50' : '$muted100'}
      sx={{ _dark: { bg: running ? '$primary950' : '$muted800' } }}
    />
    <Box
      w={46}
      h={46}
      borderRadius="$xl"
      bg={running ? '$primary600' : '$muted500'}
      alignItems="center"
      justifyContent="center"
    >
      <Text color="$white" fontWeight="$bold" size="sm">
        OC
      </Text>
    </Box>
  </Box>
)

const EventRow = ({ event, last }) => (
  <HStack
    py="$3"
    alignItems="center"
    space="md"
    borderBottomWidth={last ? 0 : 1}
    borderColor="$borderColorCardLight"
    sx={{ _dark: { borderColor: '$borderColorCardDark' } }}
  >
    <Box
      w={38}
      h={38}
      borderRadius="$lg"
      bg="$backgroundContentLight"
      borderWidth={1}
      borderColor="$muted100"
      alignItems="center"
      justifyContent="center"
      sx={{ _dark: { bg: '$backgroundContentDark', borderColor: '$muted800' } }}
    >
      <Text size="2xs" fontWeight="$bold" color="$primary600" sx={{ _dark: { color: '$primary400' } }}>
        {(SERVICE_LABELS[event.Service] || event.Service || 'OC').slice(0, 2).toUpperCase()}
      </Text>
    </Box>
    <VStack flex={1} space="xs" minWidth={0}>
      <HStack alignItems="center" space="sm" flexWrap="wrap">
        <Text size="sm" fontWeight="$semibold">
          {event.Summary}
        </Text>
        <Badge action="error" variant="outline" borderRadius="$full" size="sm">
          <BadgeText>{SERVICE_LABELS[event.Service] || event.Service}</BadgeText>
        </Badge>
      </HStack>
      <HStack alignItems="center" space="sm" flexWrap="wrap">
        <Mono size="xs">{event.SourceIP || 'unknown source'}</Mono>
        <Text size="xs" color="$muted500">
          → port {event.DestPort || '—'}
        </Text>
      </HStack>
    </VStack>
    <Text size="xs" color="$muted500" flexShrink={0}>
      {timeAgo(event.Timestamp) || 'just now'}
    </Text>
  </HStack>
)

const ServiceCard = ({ definition, value, onToggle, onPort }) => {
  const enabled = !!value?.Enabled
  return (
    <Card
      p="$4"
      flexGrow={1}
      flexBasis={310}
      minWidth={260}
      borderColor={enabled ? '$primary200' : '$borderColorCardLight'}
      sx={{ _dark: { borderColor: enabled ? '$primary800' : '$borderColorCardDark' } }}
    >
      <VStack space="md">
        <HStack alignItems="flex-start" justifyContent="space-between" space="md">
          <HStack space="sm" alignItems="center" flex={1}>
            <Box
              w={38}
              h={38}
              borderRadius="$lg"
              alignItems="center"
              justifyContent="center"
              bg={enabled ? '$primary50' : '$backgroundContentLight'}
              sx={{ _dark: { bg: enabled ? '$primary950' : '$backgroundContentDark' } }}
            >
              <Text size="2xs" fontWeight="$bold" color={enabled ? '$primary600' : '$muted500'}>
                {definition.mark}
              </Text>
            </Box>
            <VStack flex={1} space="xs">
              <Text size="sm" fontWeight="$semibold">
                {definition.label}
              </Text>
              <Text size="xs" color="$muted500">
                {definition.description}
              </Text>
            </VStack>
          </HStack>
          <Toggle value={enabled} onPress={onToggle} label={`${definition.label} decoy`} />
        </HStack>
        <HStack alignItems="center" justifyContent="space-between" space="md">
          <Badge action="muted" variant="outline" borderRadius="$full" size="sm">
            <BadgeText>{definition.protocol}</BadgeText>
          </Badge>
          <HStack alignItems="center" space="sm">
            <Text size="xs" color="$muted500">
              Port
            </Text>
            <Input
              w={92}
              size="sm"
              borderRadius="$lg"
              borderColor="$muted300"
              sx={{ _dark: { borderColor: '$muted700' } }}
            >
              <InputField
                value={value?.Port || ''}
                onChangeText={onPort}
                keyboardType="number-pad"
                textAlign="right"
                w="$full"
                minWidth={0}
                color="$textLight900"
                sx={{ _dark: { color: '$textDark50' } }}
                accessibilityLabel={`${definition.label} port`}
              />
            </Input>
          </HStack>
        </HStack>
      </VStack>
    </Card>
  )
}

export default function Plugin() {
  const alert = useAlert()
  const [tab, setTab] = useState('overview')
  const [status, setStatus] = useState(null)
  const [events, setEvents] = useState(null)
  const [config, setConfig] = useState(null)
  const [form, setForm] = useState(formFromConfig(null))
  const [baseline, setBaseline] = useState('')
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [saving, setSaving] = useState(false)
  const [daemonBusy, setDaemonBusy] = useState(false)
  const [eventFilter, setEventFilter] = useState('all')
  const [clearConfirm, setClearConfirm] = useState(false)

  const adoptConfig = useCallback((next) => {
    const nextForm = formFromConfig(next)
    setConfig(next)
    setForm(nextForm)
    setBaseline(JSON.stringify(nextForm))
  }, [])

  const refreshStatus = useCallback(() =>
    api.get(`${PLUGIN_BASE}/status`).then(setStatus), [])

  const refreshEvents = useCallback((filter = 'all') => {
    const service = filter === 'all' ? '' : filter
    return api
      .get(`${PLUGIN_BASE}/events?limit=100&service=${encodeURIComponent(service)}`)
      .then(setEvents)
  }, [])

  const loadAll = useCallback(() => {
    setLoadError(false)
    return Promise.all([
      api.get(`${PLUGIN_BASE}/config`).then(adoptConfig),
      refreshStatus(),
      refreshEvents('all')
    ]).catch((error) => {
      setLoadError(true)
      throw error
    })
  }, [adoptConfig, refreshEvents, refreshStatus])

  useEffect(() => {
    loadAll().catch(() => {}).finally(() => setLoading(false))
  }, [loadAll])

  useEffect(() => {
    if (tab !== 'overview') return undefined
    const timer = setInterval(() => {
      refreshStatus().catch(() => {})
      refreshEvents(eventFilter).catch(() => {})
    }, status?.Running ? 5000 : 10000)
    return () => clearInterval(timer)
  }, [eventFilter, refreshEvents, refreshStatus, status?.Running, tab])

  const dirty = useMemo(() => JSON.stringify(form) !== baseline, [baseline, form])
  const activeServices = useMemo(
    () => Object.values(form.Services || {}).filter((service) => service.Enabled).length,
    [form.Services]
  )

  const setService = (key, patch) => {
    setForm((current) => ({
      ...current,
      Services: {
        ...current.Services,
        [key]: { ...current.Services[key], ...patch }
      }
    }))
  }

  const applyPreset = (preset) => {
    const enabled = new Set(PRESETS[preset])
    setForm((current) => ({
      ...current,
      Services: Object.fromEntries(
        Object.entries(current.Services).map(([key, service]) => [
          key,
          { ...service, Enabled: enabled.has(key) }
        ])
      )
    }))
  }

  const save = async () => {
    const nodeID = form.NodeID.trim()
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(nodeID)) {
      alert.error('Check identity', 'Use 1–64 letters, numbers, dots, dashes, or underscores.')
      return
    }
    const services = Object.fromEntries(
      Object.entries(form.Services).map(([key, service]) => [
        key,
        { Enabled: !!service.Enabled, Port: Number(service.Port) }
      ])
    )
    const ports = Object.values(services).map((service) => service.Port)
    if (ports.some((port) => !Number.isInteger(port) || port < 1 || port > 65535)) {
      alert.error('Check service ports', 'Every port must be a whole number between 1 and 65535.')
      return
    }
    if (new Set(ports).size !== ports.length) {
      alert.error('Check service ports', 'OpenCanary requires every configured service port to be unique.')
      return
    }
    if (!Object.values(services).some((service) => service.Enabled)) {
      alert.error('No decoys enabled', 'Enable at least one service before saving.')
      return
    }

    setSaving(true)
    try {
      const next = await api.put(`${PLUGIN_BASE}/config`, {
        NodeID: nodeID,
        IgnoreIPs: parseIgnoreList(form.IgnoreIPs),
        Services: services,
        Webhook: form.Webhook
      })
      adoptConfig(next)
      await Promise.all([refreshStatus(), refreshEvents(eventFilter)])
      alert.success('Configuration applied', 'OpenCanary restarted with the new decoy profile.')
    } catch (error) {
      alert.error('Could not apply configuration', await errorText(error, 'The plugin rejected the new settings.'))
    } finally {
      setSaving(false)
    }
  }

  const daemonAction = async (action) => {
    setDaemonBusy(true)
    try {
      const nextStatus = await api.post(`${PLUGIN_BASE}/daemon`, { Action: action })
      setStatus((current) => ({ ...current, ...nextStatus }))
      alert.success(
        action === 'restart' ? 'OpenCanary restarted' : action === 'stop' ? 'OpenCanary paused' : 'OpenCanary started',
        action === 'stop' ? 'Decoy services are no longer listening.' : 'Decoy services are listening on the SPR LAN.'
      )
    } catch (error) {
      alert.error('Daemon action failed', await errorText(error, 'OpenCanary did not complete the requested action.'))
    } finally {
      setDaemonBusy(false)
      refreshStatus().catch(() => {})
    }
  }

  const clearHistory = async () => {
    try {
      await api.delete(`${PLUGIN_BASE}/events`, {})
      await Promise.all([refreshEvents(eventFilter), refreshStatus()])
      alert.success('Event history cleared', 'The local OpenCanary alert log is empty.')
    } catch (error) {
      alert.error('Could not clear history', await errorText(error, 'The event log could not be cleared.'))
    }
  }

  if (loading) {
    return <Page><Loading text="Connecting to OpenCanary…" /></Page>
  }

  const running = !!status?.Running
  const filterOptions = [
    { value: 'all', label: 'All activity' },
    ...Object.entries(events?.ByService || {})
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([key]) => ({ value: key, label: SERVICE_LABELS[key] || key }))
  ]

  return (
    <Page>
      <ListHeader
        title="OpenCanary"
        mark="OC"
        description="Early-warning decoys for your SPR network"
        status={running ? 'Protected' : 'Paused'}
        statusAction={running ? 'success' : status?.LastError ? 'error' : 'warning'}
      >
        <Button
          size="sm"
          variant="outline"
          action="secondary"
          isDisabled={daemonBusy}
          onPress={() => daemonAction(running ? 'stop' : 'start')}
        >
          <ButtonText>{running ? 'Pause' : 'Start'}</ButtonText>
        </Button>
        <Button size="sm" variant="outline" isDisabled={daemonBusy} onPress={() => daemonAction('restart')}>
          <ButtonText>Restart</ButtonText>
        </Button>
      </ListHeader>

      <HStack space="sm" flexWrap="wrap">
        {[
          ['overview', 'Overview'],
          ['services', 'Decoy services'],
          ['presence', 'LAN presence'],
          ['settings', 'Settings']
        ].map(([value, label]) => (
          <Button
            key={value}
            size="sm"
            borderRadius="$full"
            variant={tab === value ? 'solid' : 'outline'}
            action={tab === value ? 'primary' : 'secondary'}
            onPress={() => setTab(value)}
          >
            <ButtonText>{label}</ButtonText>
          </Button>
        ))}
      </HStack>

      {loadError ? (
        <Card tone="warning">
          <HStack alignItems="center" justifyContent="space-between" flexWrap="wrap" gap="$3">
            <VStack space="xs">
              <Text fontWeight="$semibold">The control plane is not responding</Text>
              <Text size="sm" color="$muted500">OpenCanary may still be detecting traffic. Retry the management connection.</Text>
            </VStack>
            <Button size="sm" onPress={() => { setLoading(true); loadAll().catch(() => {}).finally(() => setLoading(false)) }}>
              <ButtonText>Retry</ButtonText>
            </Button>
          </HStack>
        </Card>
      ) : null}

      {tab === 'overview' ? (
        <>
          <Card p="$6">
            <HStack alignItems="center" justifyContent="space-between" flexWrap="wrap" gap="$6">
              <HStack alignItems="center" space="xl" flex={1} minWidth={280}>
                <ProtectionMark running={running} />
                <VStack space="sm" flex={1}>
                  <HStack alignItems="center" space="sm">
                    <StatusDot online={running} warn={!running && !status?.LastError} />
                    <Heading size="md">{running ? 'Monitoring the LAN' : 'Detection is paused'}</Heading>
                  </HStack>
                  <Text size="sm" color="$muted500" lineHeight="$sm" maxWidth={520}>
                    {running
                      ? `${activeServices} believable services are waiting for unexpected connections. Every interaction becomes an alert.`
                      : status?.LastError || 'Start OpenCanary to put your decoy services back online.'}
                  </Text>
                </VStack>
              </HStack>
              <VStack
                minWidth={230}
                p="$4"
                space="xs"
                borderRadius="$xl"
                bg="$backgroundContentLight"
                sx={{ _dark: { bg: '$backgroundContentDark' } }}
              >
                <Label>Canary address</Label>
                <Mono size="lg" fontWeight="$semibold">{status?.CanaryIP || '172.30.119.2'}</Mono>
                <Text size="xs" color="$muted500">Routed from every SPR LAN segment</Text>
              </VStack>
            </HStack>
          </Card>

          <HStack flexWrap="wrap" gap="$3">
            <StatTile label="Alerts · 24h" value={events?.Last24Hours ?? status?.Events24Hours ?? 0} />
            <StatTile label="Unique sources" value={events?.UniqueSources ?? status?.UniqueSources ?? 0} />
            <StatTile label="Active services" value={status?.ActiveServices ?? activeServices} />
            <StatTile label="Uptime" value={formatUptime(status?.UptimeSeconds)} mono />
          </HStack>

          <Card>
            <SectionHeader
              title="Detection pulse"
              right={<Text size="xs" color="$muted500">Last 24 hours</Text>}
            />
            <PulseChart values={events?.Hourly} />
          </Card>

          <Card>
            <SectionHeader
              title="Recent detections"
              count={events?.FilteredTotal ?? 0}
              right={
                <Button size="xs" variant="outline" action="secondary" onPress={() => refreshEvents(eventFilter)}>
                  <ButtonText>Refresh</ButtonText>
                </Button>
              }
            />
            <Segment options={filterOptions} value={eventFilter} onChange={(value) => { setEventFilter(value); refreshEvents(value) }} />
            <Box mt="$3">
              {events?.Events?.length ? (
                events.Events.slice(0, 20).map((event, index) => (
                  <EventRow key={event.ID} event={event} last={index === Math.min(19, events.Events.length - 1)} />
                ))
              ) : (
                <EmptyState
                  title="Quiet network"
                  description="No interactions match this view. That is the healthy state; OpenCanary will surface the first unexpected connection here."
                />
              )}
            </Box>
          </Card>
        </>
      ) : null}

      {tab === 'services' ? (
        <>
          <Card p="$4">
            <HStack alignItems="center" justifyContent="space-between" flexWrap="wrap" gap="$4">
              <VStack space="xs" flex={1} minWidth={240}>
                <Label>Deployment profile</Label>
                <Text size="sm" color="$muted500">
                  Start with a believable device persona, then fine-tune individual listeners.
                </Text>
              </VStack>
              <Segment
                value=""
                onChange={applyPreset}
                options={[
                  { value: 'nas', label: 'NAS appliance' },
                  { value: 'linux', label: 'Linux server' },
                  { value: 'windows', label: 'Windows server' },
                  { value: 'network', label: 'Network appliance' }
                ]}
              />
            </HStack>
          </Card>

          <HStack alignItems="center" justifyContent="space-between" flexWrap="wrap" gap="$3">
            <VStack space="xs">
              <Heading size="md">Decoy services</Heading>
              <Text size="sm" color="$muted500">{activeServices} of {SERVICES.length} listeners enabled</Text>
            </VStack>
            <HStack alignItems="center" space="sm">
              {dirty ? (
                <Badge action="warning" variant="outline" borderRadius="$full"><BadgeText>Unsaved changes</BadgeText></Badge>
              ) : null}
              <Button size="sm" isDisabled={!dirty || saving} onPress={save}>
                <ButtonText>{saving ? 'Applying…' : 'Apply profile'}</ButtonText>
              </Button>
            </HStack>
          </HStack>

          <HStack flexWrap="wrap" gap="$3" alignItems="stretch">
            {SERVICES.map((definition) => (
              <ServiceCard
                key={definition.key}
                definition={definition}
                value={form.Services[definition.key]}
                onToggle={() => setService(definition.key, { Enabled: !form.Services[definition.key]?.Enabled })}
                onPort={(Port) => setService(definition.key, { Port })}
              />
            ))}
          </HStack>

          <Card p="$4">
            <HStack alignItems="center" justifyContent="space-between" flexWrap="wrap" gap="$3">
              <Text size="sm" color="$muted500">Applying changes restarts listeners for a few seconds.</Text>
              <Button isDisabled={!dirty || saving} onPress={save}>
                <ButtonText>{saving ? 'Applying configuration…' : 'Apply configuration'}</ButtonText>
              </Button>
            </HStack>
          </Card>
        </>
      ) : null}

      {tab === 'presence' ? (
        <LanPresence
          canaryIP={status?.CanaryIP || '172.30.119.2'}
          services={config?.Services || {}}
          serviceDefinitions={SERVICES}
        />
      ) : null}

      {tab === 'settings' ? (
        <>
          <Card>
            <SectionHeader title="Canary identity" />
            <VStack space="lg">
              <TextField
                label="Node ID"
                value={form.NodeID}
                onChangeText={(NodeID) => setForm((current) => ({ ...current, NodeID }))}
                placeholder="spr-canary-01"
                helper="Included in every alert. Use a name that looks ordinary in your environment."
              />
              <VStack space="xs">
                <Text size="sm" fontWeight="$semibold">Trusted sources</Text>
                <Textarea h="$28" borderColor="$muted300" sx={{ _dark: { borderColor: '$muted700' } }}>
                  <TextareaInput
                    value={form.IgnoreIPs}
                    onChangeText={(IgnoreIPs) => setForm((current) => ({ ...current, IgnoreIPs }))}
                    placeholder={'192.168.2.10\n192.168.10.0/24'}
                    fontFamily="monospace"
                    fontSize="$sm"
                  />
                </Textarea>
                <Text size="xs" color="$muted500">One IP address or CIDR per line. Matching activity is not recorded or forwarded.</Text>
              </VStack>
            </VStack>
          </Card>

          <Card>
            <SectionHeader
              title="Alert delivery"
              right={
                <Badge
                  action={form.Webhook.Enabled ? 'success' : 'muted'}
                  variant="outline"
                  borderRadius="$full"
                >
                  <BadgeText>{form.Webhook.Enabled ? 'Enabled' : 'Local only'}</BadgeText>
                </Badge>
              }
            />
            <VStack space="lg">
              <HStack alignItems="center" justifyContent="space-between" space="md">
                <VStack flex={1} space="xs">
                  <Text size="sm" fontWeight="$semibold">Send webhook alerts</Text>
                  <Text size="xs" color="$muted500">Deliver each detection as it happens; local history is always retained.</Text>
                </VStack>
                <Toggle
                  value={form.Webhook.Enabled}
                  label="Send webhook alerts"
                  onPress={() => setForm((current) => ({
                    ...current,
                    Webhook: { ...current.Webhook, Enabled: !current.Webhook.Enabled }
                  }))}
                />
              </HStack>
              {form.Webhook.Enabled ? (
                <>
                  <VStack space="xs">
                    <Label>Destination</Label>
                    <Segment
                      value={form.Webhook.Kind}
                      onChange={(Kind) => setForm((current) => ({
                        ...current,
                        Webhook: { ...current.Webhook, Kind }
                      }))}
                      options={[
                        { value: 'generic', label: 'Webhook' },
                        { value: 'slack', label: 'Slack' },
                        { value: 'teams', label: 'Microsoft Teams' }
                      ]}
                    />
                  </VStack>
                  <TextField
                    label={config?.Webhook?.Configured && !form.Webhook.Clear ? 'Replace webhook URL' : 'Webhook URL'}
                    value={form.Webhook.URL}
                    onChangeText={(URL) => setForm((current) => ({
                      ...current,
                      Webhook: { ...current.Webhook, URL, Clear: false }
                    }))}
                    placeholder={config?.Webhook?.Configured && !form.Webhook.Clear ? 'Configured · leave blank to keep it' : 'https://…'}
                    helper="Stored as a mode-0600 secret and never returned by the API."
                    secureTextEntry
                  />
                </>
              ) : null}
              {config?.Webhook?.Configured && !form.Webhook.Clear ? (
                <HStack alignItems="center" justifyContent="space-between" flexWrap="wrap" gap="$3">
                  <Badge action="success" variant="outline" borderRadius="$full"><BadgeText>URL configured</BadgeText></Badge>
                  <Button
                    size="xs"
                    variant="outline"
                    action="negative"
                    onPress={() => setForm((current) => ({
                      ...current,
                      Webhook: { ...current.Webhook, Enabled: false, URL: '', Clear: true }
                    }))}
                  >
                    <ButtonText>Remove destination</ButtonText>
                  </Button>
                </HStack>
              ) : null}
            </VStack>
          </Card>

          <Card>
            <SectionHeader title="System" />
            <VStack space="md">
              <HStack justifyContent="space-between" alignItems="center" flexWrap="wrap" gap="$3">
                <VStack space="xs">
                  <Text size="sm" fontWeight="$semibold">OpenCanary runtime</Text>
                  <Text size="xs" color="$muted500">Version {status?.Version || '0.9.8'} · management remains inside SPR.</Text>
                </VStack>
                <Mono size="sm">{status?.CanaryIP || '172.30.119.2'}</Mono>
              </HStack>
              <HStack justifyContent="space-between" alignItems="center" flexWrap="wrap" gap="$3">
                <VStack space="xs">
                  <Text size="sm" fontWeight="$semibold">Local event history</Text>
                  <Text size="xs" color="$muted500">{events?.Total || 0} detections stored on the router.</Text>
                </VStack>
                <Button size="sm" variant="outline" action="negative" onPress={() => setClearConfirm(true)}>
                  <ButtonText>Clear history</ButtonText>
                </Button>
              </HStack>
            </VStack>
          </Card>

          <Card p="$4">
            <HStack alignItems="center" justifyContent="space-between" flexWrap="wrap" gap="$3">
              <HStack alignItems="center" space="sm">
                {dirty ? <Badge action="warning" variant="outline" borderRadius="$full"><BadgeText>Unsaved changes</BadgeText></Badge> : null}
                <Text size="sm" color="$muted500">Settings apply with one controlled restart.</Text>
              </HStack>
              <Button isDisabled={!dirty || saving} onPress={save}>
                <ButtonText>{saving ? 'Saving…' : 'Save settings'}</ButtonText>
              </Button>
            </HStack>
          </Card>
        </>
      ) : null}

      <ModalConfirm
        isOpen={clearConfirm}
        onClose={() => setClearConfirm(false)}
        onConfirm={clearHistory}
        title="Clear event history?"
        message="This permanently removes locally stored OpenCanary detections. Service configuration is not affected."
        confirmText="Clear history"
        destructive
      />
    </Page>
  )
}

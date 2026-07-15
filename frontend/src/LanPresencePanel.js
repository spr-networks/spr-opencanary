import React, { useCallback, useEffect, useMemo, useState } from 'react'
import {
  api,
  useAlert,
  Badge,
  BadgeText,
  Box,
  Button,
  ButtonText,
  Card,
  Heading,
  HStack,
  Loading,
  SectionHeader,
  Text,
  TextField,
  VStack
} from '@spr-networks/plugin-ui'
import {
  DEFAULT_PORT_MAPPINGS,
  DEFAULT_PRESENTED_DESTINATION,
  DEFAULT_SOURCE_CIDR,
  hasLanPresenceConflict,
  isManagedLanPresenceRule,
  lanPresenceRules,
  lanPresenceState,
  portMappingKey,
  portMappingsSignature,
  validatePort,
  validatePresentedDestination,
  validateSourceCIDR
} from './lanPresenceRules'

const Mono = ({ children, ...props }) => (
  <Text
    color="$textLight900"
    sx={{ '@base': { fontFamily: 'monospace' }, _dark: { color: '$textDark50' } }}
    {...props}
  >
    {children}
  </Text>
)

const responseError = async (error, fallback) => {
  try {
    const message = await error?.response?.text()
    if (message) return message
  } catch (_) {
    // Fall through to the stable user-facing message.
  }
  return fallback
}

const removeManagedRules = async (config) => {
  const rules = Array.isArray(config?.ForwardingRules) ? config.ForwardingRules : []
  const indexes = rules
    .map((rule, index) => (isManagedLanPresenceRule(rule) ? index : -1))
    .filter((index) => index >= 0)
    .sort((a, b) => b - a)

  for (const index of indexes) {
    await api.delete(`/plugins/pfw/forward/${index}`, {})
  }
}

const withRowIDs = (mappings) =>
  mappings.map((mapping, index) => ({
    ...mapping,
    id: `mapping-${mapping.protocol}-${mapping.presentedPort}-${mapping.canaryPort}-${index}`
  }))

const preferredPresentedPort = (protocol, port) => {
  const preferred = {
    'tcp:21': 2121,
    'tcp:22': 2222,
    'tcp:80': 8080,
    'tcp:443': 8443
  }
  return preferred[`${protocol}:${port}`] || port
}

export default function LanPresence({ canaryIP, services, serviceDefinitions = [] }) {
  const alert = useAlert()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [pfwAvailable, setPFWAvailable] = useState(null)
  const [pfwConfig, setPFWConfig] = useState(null)
  const [sourceCIDR, setSourceCIDR] = useState(DEFAULT_SOURCE_CIDR)
  const [presentedDestination, setPresentedDestination] = useState(
    DEFAULT_PRESENTED_DESTINATION
  )
  const [portMappings, setPortMappings] = useState(() =>
    withRowIDs(DEFAULT_PORT_MAPPINGS)
  )
  const [error, setError] = useState('')

  const enabledServices = useMemo(
    () =>
      serviceDefinitions
        .filter((definition) => services?.[definition.key]?.Enabled)
        .map((definition) => ({
          key: definition.key,
          label: definition.label,
          protocol: definition.protocol.toLowerCase(),
          port: Number(services[definition.key].Port)
        })),
    [serviceDefinitions, services]
  )

  const load = useCallback(async () => {
    try {
      const config = (await api.get('/plugins/pfw/config')) || { ForwardingRules: [] }
      const state = lanPresenceState(config, canaryIP)
      setPFWAvailable(true)
      setPFWConfig(config)
      setSourceCIDR(state.sourceCIDR || DEFAULT_SOURCE_CIDR)
      setPresentedDestination(
        state.presentedDestination || DEFAULT_PRESENTED_DESTINATION
      )
      setPortMappings(
        withRowIDs(
          state.portMappings.length ? state.portMappings : DEFAULT_PORT_MAPPINGS
        )
      )
    } catch (_) {
      setPFWAvailable(false)
      setPFWConfig(null)
    }
  }, [canaryIP])

  useEffect(() => {
    let active = true
    load()
      .catch(() => active && setError('Could not inspect PFW.'))
      .finally(() => active && setLoading(false))
    return () => {
      active = false
    }
  }, [load])

  const presence = useMemo(
    () => lanPresenceState(pfwConfig, canaryIP),
    [canaryIP, pfwConfig]
  )
  const cleanMappings = useMemo(
    () =>
      portMappings.map(({ protocol, presentedPort, canaryPort }) => ({
        protocol,
        presentedPort: presentedPort.trim(),
        canaryPort: canaryPort.trim()
      })),
    [portMappings]
  )
  const mapping = useMemo(
    () => ({
      sourceCIDR: sourceCIDR.trim(),
      presentedDestination: presentedDestination.trim(),
      portMappings: cleanMappings,
      canaryIP
    }),
    [canaryIP, cleanMappings, presentedDestination, sourceCIDR]
  )
  const sourceError = validateSourceCIDR(sourceCIDR)
  const destinationError = validatePresentedDestination(presentedDestination)
  const duplicateKeys = cleanMappings
    .map(portMappingKey)
    .filter((key, index, keys) => keys.indexOf(key) !== index)
  const mappingValidation = cleanMappings.map((entry) => {
    const errors = [
      validatePort(entry.presentedPort, 'Presented port'),
      validatePort(entry.canaryPort, 'OpenCanary port')
    ].filter(Boolean)
    if (duplicateKeys.includes(portMappingKey(entry))) {
      errors.push('This protocol and presented port are already mapped.')
    }
    const service = enabledServices.find(
      (candidate) =>
        candidate.protocol === entry.protocol &&
        candidate.port === Number(entry.canaryPort)
    )
    if (!validatePort(entry.canaryPort) && !service) {
      errors.push(
        `No enabled OpenCanary service listens on ${entry.protocol.toUpperCase()} ${entry.canaryPort}.`
      )
    }
    return { errors, service }
  })
  const hasMappingErrors = mappingValidation.some((result) => result.errors.length)
  const conflict = hasLanPresenceConflict(pfwConfig, mapping)
  const needsApply =
    !presence.configured ||
    presence.sourceCIDR !== mapping.sourceCIDR ||
    presence.presentedDestination !== mapping.presentedDestination ||
    portMappingsSignature(presence.portMappings) !==
      portMappingsSignature(cleanMappings)

  const updateMapping = (id, patch) => {
    setPortMappings((current) =>
      current.map((entry) => (entry.id === id ? { ...entry, ...patch } : entry))
    )
    setError('')
  }

  const addMapping = () => {
    const usedTargets = new Set(
      cleanMappings.map((entry) => `${entry.protocol}:${entry.canaryPort}`)
    )
    const service =
      enabledServices.find(
        (candidate) => !usedTargets.has(`${candidate.protocol}:${candidate.port}`)
      ) || enabledServices[0]
    const protocol = service?.protocol || 'tcp'
    const canaryPort = String(service?.port || 80)
    let presentedPort = preferredPresentedPort(protocol, Number(canaryPort))
    const usedPresented = new Set(cleanMappings.map(portMappingKey))
    while (usedPresented.has(`${protocol}:${presentedPort}`) && presentedPort < 65535) {
      presentedPort++
    }
    setPortMappings((current) => [
      ...current,
      {
        id: `mapping-new-${Date.now()}`,
        protocol,
        presentedPort: String(presentedPort),
        canaryPort
      }
    ])
    setError('')
  }

  const removeMapping = (id) => {
    setPortMappings((current) => current.filter((entry) => entry.id !== id))
    setError('')
  }

  const apply = async () => {
    const invalid =
      sourceError ||
      destinationError ||
      mappingValidation.flatMap((result) => result.errors)[0]
    if (invalid) {
      setError(invalid)
      return
    }
    if (!cleanMappings.length) {
      setError('Add at least one port mapping.')
      return
    }
    if (!canaryIP) {
      setError('The OpenCanary container address is not available yet.')
      return
    }

    setSaving(true)
    setError('')
    try {
      const current = await api.get('/plugins/pfw/config')
      if (hasLanPresenceConflict(current, mapping)) {
        throw new Error(
          'Another PFW flow overlaps this client, destination, protocol, and port.'
        )
      }

      await removeManagedRules(current)
      for (const rule of lanPresenceRules(mapping)) {
        await api.put('/plugins/pfw/forward', rule)
      }
      await load()
      alert.success(
        'LAN presence published',
        `${cleanMappings.length} port ${cleanMappings.length === 1 ? 'mapping is' : 'mappings are'} active at ${mapping.presentedDestination}.`
      )
    } catch (cause) {
      const message = cause?.response
        ? await responseError(cause, 'PFW could not install the managed flows.')
        : cause?.message || 'PFW could not install the managed flows.'
      setError(message)
      alert.error('Could not publish LAN presence', message)
      await load()
    } finally {
      setSaving(false)
    }
  }

  const remove = async () => {
    setSaving(true)
    setError('')
    try {
      const current = await api.get('/plugins/pfw/config')
      await removeManagedRules(current)
      await load()
      alert.success(
        'LAN presence removed',
        'The Docker-only OpenCanary address is still active inside SPR.'
      )
    } catch (cause) {
      const message = await responseError(cause, 'PFW could not remove the managed flows.')
      setError(message)
      alert.error('Could not remove LAN presence', message)
      await load()
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <Card><Loading text="Inspecting PFW flows…" /></Card>

  if (!pfwAvailable) {
    return (
      <Card tone="warning">
        <SectionHeader
          title="LAN presence"
          right={<Badge action="warning" variant="outline" borderRadius="$full"><BadgeText>PFW required</BadgeText></Badge>}
        />
        <VStack space="md">
          <Text size="sm" color="$muted600" lineHeight="$sm">
            Install and enable the SPR Programmable Firewall extension to present OpenCanary services at a chosen LAN destination.
          </Text>
          <Text size="xs" color="$muted500">
            OpenCanary remains reachable at {canaryIP || '172.30.119.2'} from networks allowed by SPR.
          </Text>
        </VStack>
      </Card>
    )
  }

  const statusText = saving
    ? 'Applying'
    : presence.configured
      ? `${presence.managedCount} ${presence.managedCount === 1 ? 'port' : 'ports'} published`
      : presence.needsRepair
        ? 'Update required'
        : 'Not configured'
  const statusAction = presence.configured
    ? 'success'
    : presence.needsRepair
      ? 'warning'
      : 'muted'

  return (
    <Card>
      <SectionHeader
        title="LAN presence"
        right={<Badge action={statusAction} variant="outline" borderRadius="$full"><BadgeText>{statusText}</BadgeText></Badge>}
      />
      <VStack space="lg">
        <Text size="sm" color="$muted500" lineHeight="$sm">
          PFW matches a client source CIDR and presented destination, then applies each port translation below to an enabled OpenCanary listener.
        </Text>

        <HStack flexWrap="wrap" gap="$3" alignItems="stretch">
          <Box
            flexGrow={1}
            flexBasis={190}
            p="$4"
            borderRadius="$xl"
            bg="$backgroundContentLight"
            sx={{ _dark: { bg: '$backgroundContentDark' } }}
          >
            <VStack space="xs">
              <Text size="2xs" color="$muted500" fontWeight="$semibold">CLIENT SOURCE</Text>
              <Mono size="md" fontWeight="$semibold">{mapping.sourceCIDR}</Mono>
              <Text size="xs" color="$muted500">PFW Client.SrcIP</Text>
            </VStack>
          </Box>
          <Box alignItems="center" justifyContent="center" px="$1">
            <Text color="$muted500" fontWeight="$bold">→</Text>
          </Box>
          <Box
            flexGrow={1}
            flexBasis={220}
            p="$4"
            borderRadius="$xl"
            bg="$primary50"
            sx={{ _dark: { bg: '$primary950' } }}
          >
            <VStack space="xs">
              <Text size="2xs" color="$primary600" fontWeight="$semibold">PRESENTED DESTINATION</Text>
              <Mono size="md" fontWeight="$semibold">{mapping.presentedDestination}</Mono>
              <Text size="xs" color="$muted500">{cleanMappings.length} port {cleanMappings.length === 1 ? 'mapping' : 'mappings'}</Text>
            </VStack>
          </Box>
          <Box alignItems="center" justifyContent="center" px="$1">
            <Text color="$muted500" fontWeight="$bold">→</Text>
          </Box>
          <Box
            flexGrow={1}
            flexBasis={190}
            p="$4"
            borderRadius="$xl"
            bg="$backgroundContentLight"
            sx={{ _dark: { bg: '$backgroundContentDark' } }}
          >
            <VStack space="xs">
              <Text size="2xs" color="$muted500" fontWeight="$semibold">OPENCANARY TARGET</Text>
              <Mono size="md" fontWeight="$semibold">{canaryIP || '172.30.119.2'}</Mono>
              <Text size="xs" color="$muted500">Enabled listener ports</Text>
            </VStack>
          </Box>
        </HStack>

        <TextField
          label="Client source CIDR"
          value={sourceCIDR}
          onChangeText={(value) => {
            setSourceCIDR(value)
            setError('')
          }}
          placeholder={DEFAULT_SOURCE_CIDR}
          helper="PFW uses this as Client.SrcIP. The default includes clients on 192.168.x.x networks."
        />

        <TextField
          label="Presented destination"
          value={presentedDestination}
          onChangeText={(value) => {
            setPresentedDestination(value)
            setError('')
          }}
          placeholder={DEFAULT_PRESENTED_DESTINATION}
          helper="The IP address or CIDR clients will connect to. PFW stores this as OriginalDst."
        />

        <VStack space="md">
          <HStack alignItems="center" justifyContent="space-between" flexWrap="wrap" gap="$3">
            <VStack space="xs">
              <Heading size="sm">Port mappings</Heading>
              <Text size="xs" color="$muted500">One managed PFW flow is created for each row.</Text>
            </VStack>
            <Button size="sm" variant="outline" action="secondary" onPress={addMapping}>
              <ButtonText>+ Add port mapping</ButtonText>
            </Button>
          </HStack>

          {portMappings.map((entry, index) => {
            const validation = mappingValidation[index]
            return (
              <Box
                key={entry.id}
                p="$4"
                borderRadius="$xl"
                borderWidth={1}
                borderColor="$muted200"
                sx={{ _dark: { borderColor: '$muted700' } }}
              >
                <VStack space="md">
                  <HStack alignItems="center" justifyContent="space-between" flexWrap="wrap" gap="$2">
                    <HStack alignItems="center" space="sm">
                      <Text size="sm" fontWeight="$semibold">Mapping {index + 1}</Text>
                      {validation.service ? (
                        <Badge action="success" variant="outline" borderRadius="$full">
                          <BadgeText>{validation.service.label}</BadgeText>
                        </Badge>
                      ) : null}
                    </HStack>
                    <Button
                      size="xs"
                      variant="outline"
                      action="negative"
                      isDisabled={portMappings.length === 1}
                      onPress={() => removeMapping(entry.id)}
                    >
                      <ButtonText>Remove</ButtonText>
                    </Button>
                  </HStack>

                  <HStack flexWrap="wrap" gap="$4" alignItems="flex-start">
                    <VStack space="sm" minWidth={140}>
                      <Text size="sm" fontWeight="$semibold">Protocol</Text>
                      <HStack space="sm">
                        {['tcp', 'udp'].map((value) => (
                          <Button
                            key={value}
                            size="xs"
                            variant={entry.protocol === value ? 'solid' : 'outline'}
                            action={entry.protocol === value ? 'primary' : 'secondary'}
                            borderRadius="$full"
                            onPress={() => updateMapping(entry.id, { protocol: value })}
                          >
                            <ButtonText>{value.toUpperCase()}</ButtonText>
                          </Button>
                        ))}
                      </HStack>
                    </VStack>
                    <Box flexGrow={1} flexBasis={220}>
                      <TextField
                        label="Presented port"
                        value={entry.presentedPort}
                        onChangeText={(value) =>
                          updateMapping(entry.id, { presentedPort: value })
                        }
                        placeholder="8080"
                        helper="Port clients connect to."
                      />
                    </Box>
                    <Box alignItems="center" justifyContent="center" pt="$8">
                      <Text color="$muted500" fontWeight="$bold">→</Text>
                    </Box>
                    <Box flexGrow={1} flexBasis={220}>
                      <TextField
                        label="OpenCanary port"
                        value={entry.canaryPort}
                        onChangeText={(value) =>
                          updateMapping(entry.id, { canaryPort: value })
                        }
                        placeholder="80"
                        helper="Enabled listener target."
                      />
                    </Box>
                  </HStack>

                  {validation.errors.map((message) => (
                    <Text key={message} size="xs" color="$error600">{message}</Text>
                  ))}
                </VStack>
              </Box>
            )
          })}
        </VStack>

        {sourceError ? <Text size="xs" color="$error600">{sourceError}</Text> : null}
        {destinationError ? <Text size="xs" color="$error600">{destinationError}</Text> : null}
        {conflict ? (
          <Text size="xs" color="$error600">
            Another PFW flow overlaps this client, destination, protocol, and a presented port.
          </Text>
        ) : null}
        {error ? <Text size="sm" color="$error600">{error}</Text> : null}

        <Card tone="warning" p="$4">
          <HStack alignItems="flex-start" space="sm">
            <Text color="$warning600" fontWeight="$bold">!</Text>
            <VStack space="xs" flex={1}>
              <Heading size="xs">Only the listed destination ports are redirected</Heading>
              <Text size="xs" color="$muted600" lineHeight="$xs">
                Clients in {mapping.sourceCIDR} connecting to {mapping.presentedDestination} will reach OpenCanary only on these mappings. Avoid ports already used by real services at that destination.
              </Text>
            </VStack>
          </HStack>
        </Card>

        <HStack justifyContent="space-between" alignItems="center" flexWrap="wrap" gap="$3">
          <VStack space="xs" flex={1} minWidth={240}>
            <Text size="sm" fontWeight="$semibold">LAN client match · no WAN exposure</Text>
            <HStack space="sm" flexWrap="wrap">
              {cleanMappings.map((entry, index) => (
                <Badge key={`${portMappingKey(entry)}-${index}`} action="muted" variant="outline" borderRadius="$full">
                  <BadgeText>{entry.protocol.toUpperCase()} {entry.presentedPort} → {entry.canaryPort}</BadgeText>
                </Badge>
              ))}
            </HStack>
          </VStack>
          <HStack space="sm" flexWrap="wrap">
            {presence.enabled ? (
              <Button size="sm" variant="outline" action="negative" isDisabled={saving} onPress={remove}>
                <ButtonText>Remove LAN presence</ButtonText>
              </Button>
            ) : null}
            <Button
              size="sm"
              isDisabled={
                saving ||
                !!sourceError ||
                !!destinationError ||
                hasMappingErrors ||
                !cleanMappings.length ||
                conflict ||
                !needsApply
              }
              onPress={apply}
            >
              <ButtonText>
                {saving
                  ? 'Applying…'
                  : presence.needsRepair
                    ? 'Update managed flows'
                    : presence.enabled
                      ? 'Update LAN presence'
                      : 'Publish LAN presence'}
              </ButtonText>
            </Button>
          </HStack>
        </HStack>
      </VStack>
    </Card>
  )
}

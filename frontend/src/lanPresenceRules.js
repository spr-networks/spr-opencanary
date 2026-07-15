export const LAN_PRESENCE_RULE_PREFIX = 'spr-opencanary-lan-'
export const DEFAULT_SOURCE_CIDR = '192.168.0.0/16'
export const DEFAULT_PRESENTED_DESTINATION = '192.168.2.253'
export const DEFAULT_PORT_MAPPINGS = [
  { protocol: 'tcp', presentedPort: '8080', canaryPort: '80' }
]

const parseIPv4 = (value) => {
  const parts = String(value || '').trim().split('.')
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) {
    return null
  }
  const octets = parts.map(Number)
  if (octets.some((octet) => octet < 0 || octet > 255)) return null
  return octets.reduce((result, octet) => result * 256 + octet, 0) >>> 0
}

const formatIPv4 = (value) =>
  [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join('.')

const parseAddress = (value, requireCIDR = false) => {
  const normalized = String(value || '').trim()
  const parts = normalized.split('/')
  if (parts.length === 1 && !requireCIDR) {
    const ip = parseIPv4(parts[0])
    return ip === null ? null : { ip, network: ip, broadcast: ip, prefix: 32 }
  }
  if (parts.length !== 2 || !/^\d{1,2}$/.test(parts[1])) return null

  const ip = parseIPv4(parts[0])
  const prefix = Number(parts[1])
  if (ip === null || prefix < 0 || prefix > 32) return null
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  const network = (ip & mask) >>> 0
  const broadcast = (network | (~mask >>> 0)) >>> 0
  return { ip, network, broadcast, prefix }
}

const privateRanges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'].map(
  (value) => parseAddress(value, true)
)

const isPrivateRange = (candidate) =>
  privateRanges.some(
    (range) =>
      candidate.network >= range.network && candidate.broadcast <= range.broadcast
  )

export const validateSourceCIDR = (value) => {
  const normalized = String(value || '').trim()
  if (!normalized.includes('/')) {
    return 'Enter the client source as a CIDR, such as 192.168.0.0/16.'
  }
  const parsed = parseAddress(normalized, true)
  if (!parsed) return 'Enter a valid IPv4 client source CIDR.'
  if (parsed.ip !== parsed.network) {
    return `Use the network address ${formatIPv4(parsed.network)}/${parsed.prefix}.`
  }
  if (!isPrivateRange(parsed)) return 'Use a private RFC1918 client source range.'
  return ''
}

export const validatePresentedDestination = (value) => {
  const normalized = String(value || '').trim()
  if (!normalized) return 'Choose the destination address clients will connect to.'
  const parsed = parseAddress(normalized)
  if (!parsed) return 'Enter a valid IPv4 address or CIDR.'
  if (normalized.includes('/') && parsed.ip !== parsed.network) {
    return `Use the network address ${formatIPv4(parsed.network)}/${parsed.prefix}.`
  }
  return ''
}

export const validatePort = (value, label = 'Port') => {
  const port = Number(String(value || '').trim())
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return `${label} must be a whole number between 1 and 65535.`
  }
  return ''
}

const normalizePortMapping = (mapping) => ({
  protocol: String(mapping?.protocol || '').toLowerCase(),
  presentedPort: String(mapping?.presentedPort || '').trim(),
  canaryPort: String(mapping?.canaryPort || '').trim()
})

export const portMappingKey = (mapping) => {
  const normalized = normalizePortMapping(mapping)
  return `${normalized.protocol}:${normalized.presentedPort}`
}

export const portMappingsSignature = (mappings = []) =>
  mappings
    .map(normalizePortMapping)
    .sort((left, right) =>
      left.protocol.localeCompare(right.protocol) ||
      Number(left.presentedPort) - Number(right.presentedPort) ||
      Number(left.canaryPort) - Number(right.canaryPort)
    )
    .map(
      (mapping) =>
        `${mapping.protocol}:${mapping.presentedPort}:${mapping.canaryPort}`
    )
    .join('|')

const ruleNameFor = (mapping) => {
  const normalized = normalizePortMapping(mapping)
  return `${LAN_PRESENCE_RULE_PREFIX}${normalized.protocol}-${normalized.presentedPort}-to-${normalized.canaryPort}`
}

export const lanPresenceRules = ({
  sourceCIDR = DEFAULT_SOURCE_CIDR,
  presentedDestination = DEFAULT_PRESENTED_DESTINATION,
  portMappings = DEFAULT_PORT_MAPPINGS,
  canaryIP
}) =>
  portMappings.map(normalizePortMapping).map((mapping) => ({
    RuleName: ruleNameFor(mapping),
    Client: { SrcIP: sourceCIDR },
    Protocol: mapping.protocol,
    OriginalDst: { IP: presentedDestination },
    OriginalDstPort: mapping.presentedPort,
    Dst: { IP: canaryIP },
    DstPort: mapping.canaryPort,
    DstInterface: '',
    Disabled: false
  }))

export const isManagedLanPresenceRule = (rule) =>
  String(rule?.RuleName || '').startsWith(LAN_PRESENCE_RULE_PREFIX)

export const lanPresenceState = (config, canaryIP) => {
  const rules = Array.isArray(config?.ForwardingRules) ? config.ForwardingRules : []
  const managed = rules.filter(isManagedLanPresenceRule)
  const sources = [...new Set(managed.map((rule) => rule?.Client?.SrcIP).filter(Boolean))]
  const destinations = [
    ...new Set(managed.map((rule) => rule?.OriginalDst?.IP).filter(Boolean))
  ]
  const sourceCIDR = sources.length === 1 ? sources[0] : ''
  const presentedDestination = destinations.length === 1 ? destinations[0] : ''
  const portMappings = managed.map((rule) => ({
    protocol: rule?.Protocol || '',
    presentedPort: rule?.OriginalDstPort || '',
    canaryPort: rule?.DstPort || ''
  }))
  const keys = portMappings.map(portMappingKey)
  const configured =
    managed.length > 0 &&
    !validateSourceCIDR(sourceCIDR) &&
    !validatePresentedDestination(presentedDestination) &&
    new Set(keys).size === keys.length &&
    managed.every((rule, index) => {
      const mapping = portMappings[index]
      return (
        ['tcp', 'udp'].includes(mapping.protocol) &&
        !validatePort(mapping.presentedPort) &&
        !validatePort(mapping.canaryPort) &&
        rule?.RuleName === ruleNameFor(mapping) &&
        rule?.Dst?.IP === canaryIP &&
        !rule?.DstInterface &&
        !rule?.Disabled
      )
    })

  return {
    sourceCIDR,
    presentedDestination,
    portMappings,
    configured,
    enabled: managed.length > 0,
    needsRepair: managed.length > 0 && !configured,
    managedCount: managed.length
  }
}

const rangesOverlap = (left, right) =>
  left.network <= right.broadcast && right.network <= left.broadcast

const portSpecIncludes = (spec, port) => {
  const normalized = String(spec || '').trim()
  if (!normalized) return true
  const parts = normalized.split('-').map(Number)
  if (parts.some((part) => !Number.isInteger(part))) return true
  return parts.length === 1
    ? parts[0] === port
    : parts.length === 2 && port >= parts[0] && port <= parts[1]
}

export const hasLanPresenceConflict = (config, mapping) => {
  const source = parseAddress(mapping?.sourceCIDR, true)
  const destination = parseAddress(mapping?.presentedDestination)
  if (!source || !destination) return false

  const desiredMappings = (mapping?.portMappings || []).map(normalizePortMapping)
  const rules = Array.isArray(config?.ForwardingRules) ? config.ForwardingRules : []
  return rules.some((rule) => {
    if (isManagedLanPresenceRule(rule) || rule?.Disabled) return false
    const otherDestination = parseAddress(rule?.OriginalDst?.IP)
    if (!otherDestination || !rangesOverlap(destination, otherDestination)) return false
    const otherSource = parseAddress(rule?.Client?.SrcIP, true)
    if (otherSource && !rangesOverlap(source, otherSource)) return false

    return desiredMappings.some(
      (desired) =>
        rule?.Protocol === desired.protocol &&
        portSpecIncludes(rule?.OriginalDstPort, Number(desired.presentedPort))
    )
  })
}

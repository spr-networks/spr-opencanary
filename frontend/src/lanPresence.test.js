import {
  hasLanPresenceConflict,
  lanPresenceRules,
  lanPresenceState,
  portMappingsSignature,
  validatePort,
  validatePresentedDestination,
  validateSourceCIDR
} from './lanPresenceRules'

const mapping = {
  sourceCIDR: '192.168.0.0/16',
  presentedDestination: '192.168.2.253',
  portMappings: [
    { protocol: 'tcp', presentedPort: '8080', canaryPort: '80' },
    { protocol: 'tcp', presentedPort: '2222', canaryPort: '22' },
    { protocol: 'udp', presentedPort: '1161', canaryPort: '161' }
  ],
  canaryIP: '172.30.119.2'
}

test('builds one PFW flow for every LAN port mapping', () => {
  const rules = lanPresenceRules(mapping)
  expect(rules).toHaveLength(3)
  expect(rules[0]).toMatchObject({
    Client: { SrcIP: '192.168.0.0/16' },
    Protocol: 'tcp',
    OriginalDst: { IP: '192.168.2.253' },
    OriginalDstPort: '8080',
    Dst: { IP: '172.30.119.2' },
    DstPort: '80'
  })
  expect(rules[1]).toMatchObject({ OriginalDstPort: '2222', DstPort: '22' })
  expect(rules[2]).toMatchObject({ Protocol: 'udp', DstPort: '161' })
})

test('validates the client source, destination, and ports', () => {
  expect(validateSourceCIDR('192.168.0.0/16')).toBe('')
  expect(validateSourceCIDR('192.168.0.1/16')).toMatch(/network address/)
  expect(validatePresentedDestination('192.168.2.253')).toBe('')
  expect(validatePresentedDestination('not-an-ip')).toMatch(/valid IPv4/)
  expect(validatePort('8080')).toBe('')
  expect(validatePort('70000', 'Presented port')).toMatch(/Presented port/)
})

test('compares port mappings independently of display order', () => {
  expect(portMappingsSignature(mapping.portMappings)).toBe(
    portMappingsSignature([...mapping.portMappings].reverse())
  )
})

test('recognizes a complete managed multi-port mapping', () => {
  const rules = lanPresenceRules(mapping)
  expect(lanPresenceState({ ForwardingRules: rules }, mapping.canaryIP)).toMatchObject({
    sourceCIDR: '192.168.0.0/16',
    presentedDestination: '192.168.2.253',
    configured: true,
    enabled: true,
    needsRepair: false,
    managedCount: 3
  })
})

test('detects a foreign flow overlapping any presented port', () => {
  const config = {
    ForwardingRules: [
      {
        RuleName: 'someone-else',
        Client: { SrcIP: '192.168.10.0/24' },
        Protocol: 'tcp',
        OriginalDst: { IP: '192.168.2.253' },
        OriginalDstPort: '8000-9000'
      }
    ]
  }
  expect(hasLanPresenceConflict(config, mapping)).toBe(true)
  expect(
    hasLanPresenceConflict(config, { ...mapping, sourceCIDR: '10.0.0.0/8' })
  ).toBe(false)
})

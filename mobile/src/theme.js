// CyberGuard AI — Dark cybersecurity theme
export const colors = {
  background:   '#0a0e1a',
  surface:      '#111827',
  card:         '#1a2235',
  border:       '#1f2d45',

  primary:      '#00d4ff',   // Cyan — main accent
  success:      '#00e676',   // Green — safe / ok
  warning:      '#ffab00',   // Amber — medium severity
  danger:       '#ff1744',   // Red — critical
  high:         '#ff6d00',   // Orange — high severity
  info:         '#448aff',   // Blue — info

  textPrimary:  '#e8f4fd',
  textSecondary:'#7a8fa6',
  textMuted:    '#3d5166',

  // Severity colours
  critical: '#ff1744',
  high:     '#ff6d00',
  medium:   '#ffab00',
  low:      '#448aff',
};

export const severity = {
  critical: { color: colors.critical, bg: '#2d0a14', label: 'CRITICAL' },
  high:     { color: colors.high,     bg: '#2d1500', label: 'HIGH' },
  medium:   { color: colors.medium,   bg: '#2d2000', label: 'MEDIUM' },
  low:      { color: colors.low,      bg: '#0a1a3d', label: 'LOW' },
  info:     { color: colors.info,     bg: '#0a1030', label: 'INFO' },
};

export const typography = {
  h1: { fontSize: 24, fontWeight: '700', color: colors.textPrimary },
  h2: { fontSize: 18, fontWeight: '600', color: colors.textPrimary },
  h3: { fontSize: 15, fontWeight: '600', color: colors.textPrimary },
  body: { fontSize: 14, color: colors.textSecondary },
  caption: { fontSize: 12, color: colors.textMuted },
  mono: { fontSize: 12, fontFamily: 'monospace', color: colors.textSecondary },
};

export const spacing = {
  xs: 4, sm: 8, md: 16, lg: 24, xl: 32,
};

export const radius = {
  sm: 6, md: 10, lg: 16,
};

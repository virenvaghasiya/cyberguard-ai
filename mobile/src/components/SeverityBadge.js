import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { severity as sev } from '../theme';

export default function SeverityBadge({ level = 'info', small = false }) {
  const s = sev[level] || sev.info;
  return (
    <View style={[styles.badge, { backgroundColor: s.bg, borderColor: s.color }, small && styles.small]}>
      <Text style={[styles.label, { color: s.color }, small && styles.smallLabel]}>
        {s.label}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  badge: {
    borderRadius: 4,
    borderWidth: 1,
    paddingHorizontal: 8,
    paddingVertical: 3,
    alignSelf: 'flex-start',
  },
  small: { paddingHorizontal: 6, paddingVertical: 2 },
  label: { fontSize: 11, fontWeight: '700', letterSpacing: 0.5 },
  smallLabel: { fontSize: 9 },
});

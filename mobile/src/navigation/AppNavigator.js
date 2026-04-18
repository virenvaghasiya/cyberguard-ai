import React from 'react';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { Text } from 'react-native';
import { colors } from '../theme';

import DashboardScreen   from '../screens/DashboardScreen';
import AlertsScreen      from '../screens/AlertsScreen';
import NetworkScreen     from '../screens/NetworkScreen';
import ScanScreen        from '../screens/ScanScreen';
import SystemScreen      from '../screens/SystemScreen';
import SettingsScreen    from '../screens/SettingsScreen';

const Tab = createBottomTabNavigator();

const ICONS = {
  Dashboard: '📊',
  Alerts:    '🔔',
  Network:   '🌐',
  Scan:      '🔍',
  System:    '🖥️',
  Settings:  '⚙️',
};

export default function AppNavigator() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        headerShown: false,
        tabBarStyle: {
          backgroundColor: colors.surface,
          borderTopColor: colors.border,
          borderTopWidth: 1,
          paddingBottom: 4,
          height: 60,
        },
        tabBarActiveTintColor: colors.primary,
        tabBarInactiveTintColor: colors.textMuted,
        tabBarLabelStyle: { fontSize: 10, marginBottom: 4 },
        tabBarIcon: ({ color }) => (
          <Text style={{ fontSize: 20 }}>{ICONS[route.name]}</Text>
        ),
      })}
    >
      <Tab.Screen name="Dashboard" component={DashboardScreen} />
      <Tab.Screen name="Alerts"    component={AlertsScreen} />
      <Tab.Screen name="Network"   component={NetworkScreen} />
      <Tab.Screen name="Scan"      component={ScanScreen} />
      <Tab.Screen name="System"    component={SystemScreen} />
      <Tab.Screen name="Settings"  component={SettingsScreen} />
    </Tab.Navigator>
  );
}

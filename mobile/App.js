import 'react-native-gesture-handler';
import React from 'react';
import { NavigationContainer, DarkTheme } from '@react-navigation/native';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { colors } from './src/theme';
import AppNavigator from './src/navigation/AppNavigator';

// Extend DarkTheme so React Navigation v7 has all required font definitions
const CyberTheme = {
  ...DarkTheme,
  colors: {
    ...DarkTheme.colors,
    primary:      colors.primary,
    background:   colors.background,
    card:         colors.surface,
    text:         colors.textPrimary,
    border:       colors.border,
    notification: colors.danger,
  },
};

export default function App() {
  return (
    <SafeAreaProvider>
      <NavigationContainer theme={CyberTheme}>
        <StatusBar style="light" backgroundColor={colors.background} />
        <AppNavigator />
      </NavigationContainer>
    </SafeAreaProvider>
  );
}

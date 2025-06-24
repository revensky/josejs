import 'jest-extended';

import { createDefaultPreset } from 'ts-jest';

export const testEnvironment = 'node';

export default {
  ...createDefaultPreset(),
  setupFilesAfterEnv: ['jest-extended/all'],
};

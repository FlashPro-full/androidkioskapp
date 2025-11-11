import QRCode from 'qrcode';

export interface ProvisioningExtras {
  portal_url: string;
  device_id: string;
  device_token: string;
  allowed_package: string;
  initial_pin: string;
}

export function buildProvisioningPayload(extras: ProvisioningExtras) {
  return {
    'android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME':
      process.env.DEVICE_ADMIN_COMPONENT ??
      'com.example.androidlauncher/.admin.KioskDeviceAdminReceiver',
    'android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE': {
      portal_url: extras.portal_url,
      device_id: extras.device_id,
      device_token: extras.device_token,
      allowed_package: extras.allowed_package,
      initial_pin: extras.initial_pin,
    },
  };
}

export async function generateProvisioningQr(extras: ProvisioningExtras) {
  const payload = buildProvisioningPayload(extras);
  const json = JSON.stringify(payload);
  const dataUrl = await QRCode.toDataURL(json, {
    errorCorrectionLevel: 'M',
    margin: 1,
    width: 280,
  });

  return {
    image: dataUrl,
    json: JSON.stringify(payload, null, 2),
  };
}


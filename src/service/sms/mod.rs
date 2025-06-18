use tracing::info;

/// Send a verification code for SMS MFA registration.
///
/// # Arguments
///
/// * `phone_number` - The recipient's phone number.
/// * `verification_code` - The verification code to send.
///
/// # Returns
///
/// * `Result<(), String>` - Returns Ok if the SMS is sent successfully, or an error if it fails.
pub async fn send_mfa_verification_sms(
    phone_number: &str,
    verification_code: &str,
) -> Result<(), String> {
    // In a real application, you would implement SMS sending here
    // using SMS gateways or third-party services like Twilio, Nexmo, etc.
    // For now, we'll simulate sending by logging the SMS content

    let sms_body = format!(
        "Your verification code for SMS MFA registration is: {}. This code will expire in 15 minutes.",
        verification_code
    );

    // Log SMS details for demonstration
    info!("Sending MFA verification SMS to: {}", phone_number);
    info!("Body: {}", sms_body);

    // In a real implementation, you would send the SMS here
    // For now, return success
    Ok(())
}

/// Send a verification code for SMS MFA authentication.
///
/// # Arguments
///
/// * `phone_number` - The recipient's phone number.
/// * `verification_code` - The verification code to send.
///
/// # Returns
///
/// * `Result<(), String>` - Returns Ok if the SMS is sent successfully, or an error if it fails.
pub async fn send_mfa_authentication_sms(
    phone_number: &str,
    verification_code: &str,
) -> Result<(), String> {
    // In a real application, you would implement SMS sending here
    // using SMS gateways or third-party services like Twilio, Nexmo, etc.
    // For now, we'll simulate sending by logging the SMS content

    let sms_body = format!(
        "Your authentication code for login is: {}. This code will expire in 15 minutes.",
        verification_code
    );

    // Log SMS details for demonstration
    info!("Sending MFA authentication SMS to: {}", phone_number);
    info!("Body: {}", sms_body);

    // In a real implementation, you would send the SMS here
    // For now, return success
    Ok(())
}

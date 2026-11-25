/**
 * Deploy this Google Apps Script as a Web App while signed in as
 * hesh25012006@gmail.com.
 *
 * Set Script Property GMAIL_RELAY_SECRET to the same random secret configured
 * as GMAIL_RELAY_SECRET in Railway.
 */
function doPost(e) {
  try {
    const payload = JSON.parse((e && e.postData && e.postData.contents) || "{}");
    const expectedSecret = PropertiesService.getScriptProperties().getProperty("GMAIL_RELAY_SECRET");

    if (!expectedSecret || payload.secret !== expectedSecret) {
      return jsonResponse({ ok: false, error: "Unauthorized" });
    }

    const recipient = String(payload.to || "").trim();
    const subject = String(payload.subject || "TLS Monitor Notification");
    const body = String(payload.body || "");
    if (!recipient || !body) {
      return jsonResponse({ ok: false, error: "Missing recipient or message body" });
    }

    const options = { name: String(payload.senderName || "Haresh") };
    if (payload.pdfBase64) {
      const bytes = Utilities.base64Decode(payload.pdfBase64);
      const filename = String(payload.fileName || "TLS_Security_Report.pdf");
      options.attachments = [Utilities.newBlob(bytes, "application/pdf", filename)];
    }

    GmailApp.sendEmail(recipient, subject, body, options);
    return jsonResponse({ ok: true });
  } catch (error) {
    return jsonResponse({ ok: false, error: String(error && error.message || error) });
  }
}

function jsonResponse(value) {
  return ContentService.createTextOutput(JSON.stringify(value))
    .setMimeType(ContentService.MimeType.JSON);
}

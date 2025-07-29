const { GoogleSpreadsheet } = require('google-spreadsheet');

const SHEET_ID = process.env.GOOGLE_SHEET_ID;
const CLIENT_EMAIL = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL;
const PRIVATE_KEY = process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n');

const doc = new GoogleSpreadsheet(SHEET_ID);

async function appendToSheet({ clickId, zona, country, isHuman, timestamp }) {
  await doc.useServiceAccountAuth({
    client_email: CLIENT_EMAIL,
    private_key: PRIVATE_KEY
  });

  await doc.loadInfo();
  const sheet = doc.sheetsByIndex[0];

  await sheet.addRow({
    ClickID: clickId,
    Zona: zona,
    Country: country,
    Status: isHuman ? 'Human' : 'Bot',
    Timestamp: timestamp
  });
}

module.exports = {
  appendToSheet
};
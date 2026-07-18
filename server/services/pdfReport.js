/**
 * pdfReport.js
 * -----------------------------------------------------------------------
 * Renders a scan result into a professional PDF report: cover summary,
 * severity breakdown, and every finding with its explanation and
 * remediation. Built with pdfkit (pure JS, no headless browser needed).
 */

const PDFDocument = require('pdfkit');

const SEVERITY_COLOR = {
  critical: '#B02A2A',
  high: '#C4581A',
  medium: '#B8860B',
  low: '#3B6EA5',
  info: '#5C6B7A',
};

const SEVERITY_LABEL = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

function generateReportPdf(scanResult) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 50, bufferPages: true });
    const chunks = [];
    doc.on('data', (chunk) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    renderCoverSection(doc, scanResult);
    renderFindings(doc, scanResult);
    renderFooterPageNumbers(doc);

    doc.end();
  });
}

function renderCoverSection(doc, result) {
  doc.font('Helvetica-Bold').fontSize(20).fillColor('#111111').text('Website Security Audit Report');
  doc.moveDown(0.3);
  doc.font('Helvetica').fontSize(11).fillColor('#444444').text(`Target: ${result.url}`);
  doc.text(`Scanned: ${new Date(result.scannedAt).toLocaleString()}`);
  doc.text(`HTTP Status: ${result.httpStatus}   |   Scan duration: ${result.durationMs}ms`);
  doc.moveDown(1);

  // Grade + score box
  const gradeColor = { A: '#2E9E90', B: '#2E9E90', C: '#B8860B', D: '#C4581A', F: '#B02A2A' }[result.grade] || '#444444';
  const boxY = doc.y;
  doc.roundedRect(50, boxY, 495, 70, 6).fillAndStroke('#F7F6F2', '#DDDAD0');
  doc.fillColor(gradeColor).font('Helvetica-Bold').fontSize(32).text(result.grade, 68, boxY + 16, { width: 60 });
  doc.fillColor('#111111').font('Helvetica-Bold').fontSize(13).text(`Score: ${result.score} / 100`, 140, boxY + 16);
  doc.font('Helvetica').fontSize(10).fillColor('#555555').text(
    `${result.counts.critical || 0} Critical   ${result.counts.high || 0} High   ${result.counts.medium || 0} Medium   ${result.counts.low || 0} Low`,
    140,
    boxY + 38
  );
  doc.y = boxY + 90;

  doc.moveDown(0.5);
  doc.font('Helvetica-Bold').fontSize(12).fillColor('#111111').text('Severity Scale');
  doc.font('Helvetica').fontSize(9.5).fillColor('#444444');
  doc.text('This report uses the same four working severity tiers as CVSS and major bug bounty programs:');
  const scaleNotes = [
    ['CRITICAL', 'Immediate, confirmed impact - e.g. exposed credentials, broken authentication trust.'],
    ['HIGH', 'Serious weakness that materially increases risk under realistic conditions.'],
    ['MEDIUM', 'Meaningful gap in defense-in-depth; not immediately exploitable alone.'],
    ['LOW', 'Best-practice gap or minor information disclosure.'],
  ];
  scaleNotes.forEach(([label, desc]) => {
    doc.font('Helvetica-Bold').fillColor(SEVERITY_COLOR[label.toLowerCase()]).fontSize(9.5).text(label + '  ', { continued: true });
    doc.font('Helvetica').fillColor('#444444').text(desc);
  });

  doc.moveDown(1);
}

function renderFindings(doc, result) {
  doc.moveDown(0.5);
  doc.font('Helvetica-Bold').fontSize(14).fillColor('#111111').text('Findings');
  doc.moveDown(0.3);

  if (result.findings.length === 0) {
    doc.font('Helvetica').fontSize(10.5).fillColor('#2E9E90').text('No issues found across the checks performed.');
    return;
  }

  result.findings.forEach((f, idx) => {
    if (doc.y > 680) doc.addPage();

    const color = SEVERITY_COLOR[f.severity] || '#444444';
    const startY = doc.y;

    // Small colored severity marker next to the title, instead of a
    // full-height bar (which would require knowing the block's final
    // height before drawing it).
    doc.rect(50, startY + 3, 8, 8).fill(color);
    doc.fillColor('#111111');

    doc.font('Helvetica-Bold').fontSize(11).text(`${idx + 1}. ${f.title}`, 66, startY, { width: 476 });
    doc.font('Helvetica-Bold').fontSize(8.5).fillColor(color).text(
      `${SEVERITY_LABEL[f.severity] || f.severity.toUpperCase()}  \u00b7  ${f.category}`,
      66,
      doc.y + 2
    );
    doc.moveDown(0.3);

    if (f.explanation) {
      doc.font('Helvetica-Bold').fontSize(9).fillColor('#333333').text('What this means: ', 66, doc.y, { continued: true, width: 476 });
      doc.font('Helvetica').fillColor('#333333').text(f.explanation, { width: 476 });
      doc.moveDown(0.2);
    }

    doc.font('Helvetica-Bold').fontSize(9).fillColor('#333333').text('Detail: ', 66, doc.y, { continued: true, width: 476 });
    doc.font('Helvetica').fillColor('#333333').text(f.detail || '-', { width: 476 });
    doc.moveDown(0.2);

    if (f.remediation) {
      doc.font('Helvetica-Bold').fontSize(9).fillColor('#2E6B5F').text('Fix: ', 66, doc.y, { continued: true, width: 476 });
      doc.font('Helvetica').fillColor('#2E6B5F').text(f.remediation, { width: 476 });
    }

    doc.moveDown(0.9);
  });
}

function renderFooterPageNumbers(doc) {
  const range = doc.bufferedPageRange();
  const originalBottomMargin = doc.page.margins.bottom;

  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    // pdfkit auto-paginates if the text() start position falls below the
    // margin box, even with an explicit y coordinate - temporarily
    // zeroing the bottom margin is the standard workaround for footers.
    doc.page.margins.bottom = 0;
    const footerY = doc.page.height - 35;
    doc.font('Helvetica').fontSize(8).fillColor('#999999').text(
      `Page ${i + 1} of ${range.count}   |   Generated by Website Security Auditor`,
      50,
      footerY,
      { width: 495, align: 'center', lineBreak: false }
    );
    doc.page.margins.bottom = originalBottomMargin;
  }
}

module.exports = { generateReportPdf };

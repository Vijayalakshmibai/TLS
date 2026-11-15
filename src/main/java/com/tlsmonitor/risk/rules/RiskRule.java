package com.tlsmonitor.risk.rules;

import com.tlsmonitor.inspection.entity.CertificateDetails;
import com.tlsmonitor.inspection.entity.TLSScanResult;
import com.tlsmonitor.risk.entity.SecurityFinding;

import java.util.List;

public interface RiskRule {
    String getRuleCode();
    String getRuleName();
    List<SecurityFinding> evaluate(TLSScanResult scan, CertificateDetails cert);
}

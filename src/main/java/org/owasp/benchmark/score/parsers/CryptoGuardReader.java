package org.owasp.benchmark.score.parsers;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmark.score.BenchmarkScore;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

public class CryptoGuardReader extends Reader {

    public TestResults parse(File f) throws Exception {
        String content = new String(Files.readAllBytes(Paths.get(f.getPath())));

        JSONArray arr = new JSONArray(content);
        TestResults tr = new TestResults("CryptoGuard", false, TestResults.ToolType.SAST);

        for (int i = 0; i < arr.length(); i++) {
            TestCaseResult tcr = parseCryptoGuardFinding( arr.getJSONObject(i) );
            if (tcr != null) tr.put( tcr );
        }
        return tr;
    }

    private TestCaseResult parseCryptoGuardFinding(JSONObject jsonObject) {
       try {
           TestCaseResult tcr = new TestCaseResult();
           // get the testcase name
           String targetSources = jsonObject.getJSONObject("Target").getJSONArray("TargetSources").getString(0);
           String caseFullName = targetSources.substring(targetSources.lastIndexOf("/") + 1);
           String caseName = caseFullName.split("\\.")[0];
           tcr.setTestCaseName(caseName);
           if (caseName.startsWith(BenchmarkScore.TESTCASENAME)) {
               try {
                   String testNumber = caseName.substring( BenchmarkScore.TESTCASENAME.length() );
                   tcr.setNumber(Integer.parseInt(testNumber));
               } catch (Exception e) {
                  return null;
               }
           }
           if (jsonObject.getJSONArray("Issues").length() > 0) {
                JSONArray issues = jsonObject.getJSONArray("Issues");
                tcr.setCWE(figureCWE(issues));
           }
           return tcr;
       } catch (Exception e) {
           e.printStackTrace();
       }
       return null;
    }

    private int figureCWE(JSONArray issues) {
        int cwe = 0;
        // since the CWE number is not matching with the OWASP, use description to match
        if (issues.getJSONObject(0).getString("Description").contains("PRNG")) {
           cwe = 330;
        }
        if (issues.getJSONObject(0).getString("Description").contains("crypto")) {
            cwe = 327;
        }
        if (issues.getJSONObject(0).getString("Description").contains("hash")) {
            cwe = 328;
        }
        return cwe;
    }
}

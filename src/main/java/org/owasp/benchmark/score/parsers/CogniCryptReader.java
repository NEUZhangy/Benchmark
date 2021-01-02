package org.owasp.benchmark.score.parsers;

import org.bouncycastle.util.test.Test;
import org.json.JSONArray;
import org.owasp.benchmark.score.BenchmarkScore;

import javax.xml.bind.ParseConversionEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public class CogniCryptReader extends Reader{
    public TestResults parse(File f) throws Exception {
        TestResults tr = new TestResults("CogniCrypt", false, TestResults.ToolType.SAST);
        String thisLine;
        List<String> lines = new ArrayList<>();
        List<Integer> indexes = new ArrayList<>();

        try {
            String caseName = null;
            BufferedReader br = new BufferedReader(new FileReader(f));
            while ((thisLine = br.readLine()) != null) {
                if (thisLine.contains("Findings in Java Class: ")) {
                    lines.add(thisLine);
                    break;
                }
            }
            while ((thisLine = br.readLine()) != null) {
                if (lines.get(lines.size() -1).contains("Findings in Java Class: ")) {
                    indexes.add(lines.size() - 1);
                }
                lines.add(thisLine);
            }
            for (int i = 0; i < indexes.size(); i++){
               int start = indexes.get(i);
               int end = i == indexes.size() - 1 ? lines.size() : indexes.get(i + 1);
               TestCaseResult tcr = parseCogniCryptFinding(lines, start, end);
               tr.put(tcr);
            }
        } catch(Exception e) {
            e.printStackTrace();
        }

        return tr;
    }

    private TestCaseResult parseCogniCryptFinding(List<String> lines, int start, int end) {
        TestCaseResult tcr = new TestCaseResult();
        boolean found = false;
        for (int i = start; i < end; i++) {
            String line = lines.get(i);
            if (line.contains("Findings in Java Class")) {
                String caseName = line.split(":")[1].trim();
                tcr.setTestCaseName(caseName);
                String testNumber = caseName.substring(BenchmarkScore.TESTCASENAME.length());
                tcr.setNumber(Integer.parseInt(testNumber));
            }
            if (line.contains("ConstraintError") || line.contains("RequiredPredicateError"))  {
                if (line.contains("crypto")  ) {
                    tcr.setCWE(327);
                }
                if (line.contains("MessageDigest")) {
                    tcr.setCWE(328);
                }
                if (line.contains("Random")) {
                    tcr.setCWE(330);
                }
            }
        }
        return tcr;
    }


}

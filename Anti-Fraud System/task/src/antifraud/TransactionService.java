package antifraud;

import org.apache.commons.validator.routines.checkdigit.LuhnCheckDigit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

@Service
public class TransactionService {
    Logger logger = LoggerFactory.getLogger(TransactionService.class);
    private final String regex = "^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$";
    private final Pattern pattern = Pattern.compile(regex);

    @Autowired
    private SuspiciousIpRepository ipRepo;

    @Autowired
    private StolenCardRepository cardRepo;

    public ResponseEntity makePurchase(Map<String, String> map) {
        Map<String, Object> result = new HashMap<>();
        String str = map.get("amount");
        String ip = map.get("ip");
        String number = map.get("number");
        String info = "";
        String resultValue = "PROHIBITED";
        if (cardRepo.findByNumber(number).isPresent()) {
            info = "card-number";
        }
        if (ipRepo.findByIp(ip).isPresent()) {
            info = "".equals(info) ? "ip" : info + ", ip";
        }
        Long amount;
        try {
            amount = Long.parseLong(str);
        } catch (NumberFormatException e) {
            amount = 0L;
        }
        if (amount <= 0) {
            result.put("amount", amount);
            result.put("info", "none");
            return new ResponseEntity(result , HttpStatus.BAD_REQUEST);
        } else if (amount <= 200 && "".equals(info)) {
            result.put("result", "ALLOWED");
            result.put("info", "none");
            return new ResponseEntity(result, HttpStatus.OK);
        } else {
            if (amount <= 1500 && "".equals(info)) {
                resultValue = "MANUAL_PROCESSING";
                info = "amount";
            } else  if (amount > 1500) {
                info = "".equals(info) ? "amount" : "amount, "+info;
            }
        }
        result.put("result", resultValue);
        result.put("info", info);
        return new ResponseEntity(result, HttpStatus.OK);
    }

    public ResponseEntity addSuspiciousIp(Map<String, Object> map) {
        String ip = map.get("ip").toString();
        if (ip != null && pattern.matcher(ip).find()) {
            Optional<SuspiciousIp> optional = ipRepo.findByIp(ip);
            if (optional.isPresent()) {
                return new ResponseEntity(HttpStatus.CONFLICT);
            }
            SuspiciousIp suspiciousIp = new SuspiciousIp(ip);
            suspiciousIp = ipRepo.save(suspiciousIp);
            map.put("id", suspiciousIp.getId());
            return new ResponseEntity(map, HttpStatus.OK);
        }
        return new ResponseEntity(HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity getSuspiciousIp() {
        List<SuspiciousIp> list = ipRepo.findAll();
        List<Map<String,Object>> result = new ArrayList<>();
        for (SuspiciousIp ip : list) {
            Map<String, Object> map = new HashMap<>();
            map.put("id", ip.getId());
            map.put("ip", ip.getIp());
            result.add(map);
        }
        return new ResponseEntity(result, HttpStatus.OK);   }

    public ResponseEntity deleteSuspiciousIp(String ip) {
        if (ip != null && pattern.matcher(ip).find()) {
            Optional<SuspiciousIp> optional = ipRepo.findByIp(ip);
            if (optional.isEmpty()) {
                return new ResponseEntity(HttpStatus.NOT_FOUND);
            }
            ipRepo.delete(optional.get());
            Map<String, Object> map = new HashMap<>();
            map.put("status", "IP " + ip + " successfully removed!");
            return new ResponseEntity(map, HttpStatus.OK);
        }
        return new ResponseEntity(HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity addStolenCard(Map<String, Object> map) {
        String number = map.get("number").toString();
        if (number != null && LuhnCheckDigit.LUHN_CHECK_DIGIT.isValid(number)) {
            Optional<StolenCard> optional = cardRepo.findByNumber(number);
            if (optional.isPresent()) {
                return new ResponseEntity(HttpStatus.CONFLICT);
            }
            StolenCard stolenCard = new StolenCard(number);
            stolenCard = cardRepo.save(stolenCard);
            map.put("id", stolenCard.getId());
            return new ResponseEntity(map, HttpStatus.OK);
        }
        return new ResponseEntity(HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity getStolenCards() {
        List<StolenCard> list = cardRepo.findAll();
        List<Map<String,Object>> result = new ArrayList<>();
        for (StolenCard card : list) {
            Map<String, Object> map = new HashMap<>();
            map.put("id", card.getId());
            map.put("number", card.getNumber());
            result.add(map);
        }
        return new ResponseEntity(result, HttpStatus.OK);
    }

    public ResponseEntity deleteStolenCard(String number) {
        if (number != null && LuhnCheckDigit.LUHN_CHECK_DIGIT.isValid(number)) {
            Optional<StolenCard> optional = cardRepo.findByNumber(number);
            if (optional.isEmpty()) {
                return new ResponseEntity(HttpStatus.NOT_FOUND);
            }
            cardRepo.delete(optional.get());
            Map<String, Object> map = new HashMap<>();
            map.put("status", "Card " + number + " successfully removed!");
            return new ResponseEntity(map, HttpStatus.OK);
        }
        return new ResponseEntity(HttpStatus.BAD_REQUEST);
    }
}

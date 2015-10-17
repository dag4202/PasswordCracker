import edu.rit.pj2.Task;
import java.util.concurrent.ConcurrentHashMap;
import edu.rit.pj2.Loop;
import java.security.MessageDigest;

public class PasswordCrack2 extends Task{
    
    private static final char[] hexChars = {'0', '1', '2', '3', '4',
        '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    ConcurrentHashMap<String, String> found;
    
    private void permute(final String prefix, final int depth) throws Exception{
        switch (depth) {
            case 0:
	        return;
	    default:
	        parallelFor(0, 35).exec (new Loop() {
                    public void run (int i) {
                        String newPass;
                        if (i < 10){
			    newPass = prefix + ((char) (i + 48));
			} else {
                            newPass = prefix + ((char) (i + 87));
			}
			try{
			    found.put(getHash(newPass), newPass);
			    permute(newPass, depth - 1);
			} catch (Exception e) {
                            System.exit(0);
			}
		    }
		});
		break;
	}
	
    }
    public void main (String [] args) throws Exception{
        if (args.length != 1) usage();
        found = new ConcurrentHashMap<String, String> (1727604, 1f);
        permute("", 4);
	while (found.size() < 1727604);
	System.out.println(found.size());
	

    }

    private static void usage(){
        System.out.println("Usage: java pj2 PasswordCrack2 <databasefile>");
	System.exit(0);

    }

    private static String byteArrayToString (byte [] data){
        char[] result = new char[2 * data.length];
	int j = 0;
	for (int i = 0; i < data.length; i++){
            result[j++] = hexChars[(data[i] & 0xFF) / 16]; 
	    result[j++] = hexChars[(data[i] & 0xFF) % 16];
	}
	return String.valueOf(result);
    }

    private static String getHash(String password) throws Exception{
        MessageDigest md = MessageDigest.getInstance ("SHA-256");
	byte[] data = password.getBytes ("UTF-8");
	md.update (data);
	byte[] digest = md.digest();
	return byteArrayToString(digest);
    }




}

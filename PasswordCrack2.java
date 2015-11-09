import edu.rit.pj2.Task;
import java.util.concurrent.ConcurrentHashMap;
import edu.rit.pj2.Loop;
import edu.rit.pj2.Section;
import edu.rit.pj2.vbl.IntVbl;
import edu.rit.pj2.WorkQueue;
import edu.rit.pj2.ObjectLoop;
import java.security.MessageDigest;
import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;


/**
* Class PasswordCrack2 is a pj2 task which simultaneously stores all passwords of 
* four characters in a hashmap and matches user/hash combinations from a database 
* file, when the hashmap changes in size.
* 
* @author Dyangelo Grullon (dag4202)
* @version 0.0.1
*/
public class PasswordCrack2 extends Task{
    
    public static final int MAX_CHAR = 4;
    private static final char[] hexChars = {'0', '1', '2', '3', '4',
        '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    ConcurrentHashMap<String, String> hashes; //the hash/password combinations
    int users; //number of users
    int passwords;
    IntVbl count;//number of users matched
    final int maxHashes = totalPasswords(MAX_CHAR);//total possible hash/password combos
    WorkQueue<UserData> userQueue;

    /**
    * Class UserData encapsulates user data. Specifically the name, hash and the last
    * size of the hashmap, previously seen.
    */
    private class UserData {
        String name;
	String hash;
	int lastSize;

        /**
	* The constructor for Class UserData. 
	* @param name the user's name
	* @param hash the hash associated to the user
	*/
	public UserData(String name, String hash){
            this.name = name;
	    this.hash = hash;
	    this.lastSize = 0;
	}


    }
    /**
    * Finds and stores hash:password combinations, of a given length.  Uses a thread per character
    * per prefix
    * @param prefix the string to base all combinations from. Start with empty string
    * @param depth the max size of the password, and the depth of this recursive algorithm
    */
    private void findHashes(final String prefix, final int depth) throws Exception{
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
			    hashes.put(getHash(newPass), newPass);
			    findHashes(newPass, depth - 1);
			} catch (Exception e) {
                            System.exit(0);
			}
		    }
		});
		break;
	}
	
    }

    /**
    * The main function for the password crack task. Simultaneously finds all password hash combos
    * whilst matching all user/hash combinations in a database to hash/password combinations found.
    * @param args the arguments for this program. 
    */
    public void main (String [] args) throws Exception{
        if (args.length != 1) usage();
	//setup file stuff
	String filename = args[0];
	int userCount = 0;
	try {
	    InputStream dbStream = new FileInputStream (new File(filename));
	    BufferedReader dbReader = new BufferedReader( new InputStreamReader(dbStream));
	    userQueue = new WorkQueue<UserData>();
	    String dbline;
	    while ((dbline = dbReader.readLine()) != null){
	        String[] pairs = dbline.split("\\s+");
		userQueue.add(new UserData(pairs[0], pairs[1]));
		++userCount;
	    }
	} catch (Exception e){
	    System.out.println("No such file: " + filename);
	    System.exit(0);
	} 
        hashes = new ConcurrentHashMap<String, String> (maxHashes * 2, 0.5f);
	count = new IntVbl.Sum(0);
        parallelDo (new Section() {
	    public void run(){
	        try{
	            findHashes("", 4);
		} catch (Exception e) {
		    System.exit(0);
		}
	    }
	 }, new Section(){
            public void run() {
	        parallelFor (userQueue).exec( new ObjectLoop<UserData>() {
		    IntVbl toSum;
		    public void start() {
		        toSum = threadLocal(count);
		    }
		    public void run (UserData user){
		        int curSize;
			boolean found = false;
			while (true){
			    curSize = hashes.size();
			    if (user.lastSize != curSize){
			        if (hashes.containsKey(user.hash)){
				    found = true;
				    ++toSum.item;
				    break;
				}
			    }
			    if (curSize == maxHashes) break;
			    user.lastSize = curSize;
			}
			if (found) {
			    String password = hashes.get(user.hash);
			    System.out.println(user.name + ' ' + password);
			}
		    }

		});
	    }
	  });
	closingMessage(userCount, count.item);
        System.out.println(hashes.size());
    }

    /**
    * Computes the number of possible passwords for a given, max string length
    * @param n the max string length
    * @return the number of possible passwords
    */
    private static int totalPasswords(int n){
        if (n == 1 ) {
            return 36;
	} 
	return (int) (Math.pow(36, (double) n) + totalPasswords (n - 1));
    }

    /**
    * Prints the usage message.
    */
    private static void usage(){
        System.out.println("Usage: java pj2 PasswordCrack2 <databasefile>");
	System.exit(0);

    }

    /**
    * Converts a sha-256 byte array to a string
    * @param data the byte array
    * @return the string equivalent 
    */
    private static String byteArrayToString (byte [] data){
        char[] result = new char[2 * data.length];
	int j = 0;
	for (int i = 0; i < data.length; i++){
            result[j++] = hexChars[(data[i] & 0xFF) / 16]; 
	    result[j++] = hexChars[(data[i] & 0xFF) % 16];
	}
	return String.valueOf(result);
    }

    /**
    * Hashes a password using the sha-256 algorithm
    * @param password the password to hash
    * @return the hash of the string
    */
    private static String getHash(String password) throws Exception{
        MessageDigest md = MessageDigest.getInstance ("SHA-256");
	byte[] data = password.getBytes ("UTF-8");
	md.update (data);
	byte[] digest = md.digest();
	return byteArrayToString(digest);
    }

    /**
    * Prints the appropriate closing message
    * @param U the number of users
    * @param N the number of passwords found
    */
    private static void closingMessage(int U, int N){
        System.out.println(U + " users");
	System.out.println(N + " passwords found");
    }
}

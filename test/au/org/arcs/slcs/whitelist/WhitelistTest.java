package au.org.arcs.slcs.whitelist;

public class WhitelistTest {
	public static void main(String[] args) throws Exception {
		WhitelistService service = new WhitelistServiceImpl("whitelist.in");
		System.out.println(service.isInWhitelist("http://arcs.org.au"));
		System.out.println(service.isInWhitelist("https://arcs.org.au"));
		System.out.println(service.isInWhitelist("http://google.com/gmail"));
	}
}

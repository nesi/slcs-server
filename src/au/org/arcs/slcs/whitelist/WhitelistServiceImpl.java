package au.org.arcs.slcs.whitelist;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


public class WhitelistServiceImpl implements WhitelistService {
	
	private String whitelistFile;
	private List whitelist;
	
	public WhitelistServiceImpl(String file) throws IOException {
		whitelistFile = file;
		whitelist = new ArrayList();
		initList();
	}
	
	private void initList() throws IOException {
		BufferedReader reader = new BufferedReader(
				new FileReader(whitelistFile));
		String line = null;
		while ((line = reader.readLine()) != null) {
			if (!line.trim().equals(""))
				whitelist.add(line);
		}
		
	}

	public boolean isInWhitelist(String service) {
		for (int i = 0; i < whitelist.size(); i++) {
			String line = (String)whitelist.get(i);
			if (line.equals(service.trim()))
				return true;
			else if (line.trim().endsWith("*")){ //Wild-card matching
				String prefix = line.substring(0, line.length() - 1);
				if (service.startsWith(prefix))
					return true;
			}
		}
		return false;
	}

}

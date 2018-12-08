using System;

namespace org.bouncycastle.jce.provider.test
{

	public abstract class JceTestUtil
	{
		private JceTestUtil()
		{
		}

		internal static string[] getRegisteredAlgorithms(string prefix, string[] exclusionPatterns)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.jce.provider.BouncyCastleProvider prov = (org.bouncycastle.jce.provider.BouncyCastleProvider)java.security.Security.getProvider("BC");
			BouncyCastleProvider prov = (BouncyCastleProvider)Security.getProvider("BC");

			List matches = new ArrayList();
			Enumeration algos = prov.keys();
			while (algos.hasMoreElements())
			{
				string algo = (string)algos.nextElement();
				if (!algo.StartsWith(prefix, StringComparison.Ordinal))
				{
					continue;
				}
				string algoName = algo.Substring(prefix.Length);
				if (!isExcluded(algoName, exclusionPatterns))
				{
					matches.add(algoName);
				}
			}
			return (string[])matches.toArray(new string[matches.size()]);
		}

		private static bool isExcluded(string algoName, string[] exclusionPatterns)
		{
			for (int i = 0; i < exclusionPatterns.Length; i++)
			{
				if (algoName.Contains(exclusionPatterns[i]))
				{
					return true;
				}
			}
			return false;
		}
	}

}
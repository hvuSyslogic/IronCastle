using System;

namespace org.bouncycastle.mime.smime
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CMSAlgorithm = org.bouncycastle.cms.CMSAlgorithm;
	using Strings = org.bouncycastle.util.Strings;

	public class SMimeUtils
	{
		private static readonly Map RFC5751_MICALGS;
		private static readonly Map RFC3851_MICALGS;
		private static readonly Map STANDARD_MICALGS;
		private static readonly Map forMic;

		private static readonly byte[] nl = new byte[2];


		static SMimeUtils()
		{
			nl[0] = (byte)'\r';
			nl[1] = (byte)'\n';


			Map stdMicAlgs = new HashMap();

			stdMicAlgs.put(CMSAlgorithm.MD5, "md5");
			stdMicAlgs.put(CMSAlgorithm.SHA1, "sha-1");
			stdMicAlgs.put(CMSAlgorithm.SHA224, "sha-224");
			stdMicAlgs.put(CMSAlgorithm.SHA256, "sha-256");
			stdMicAlgs.put(CMSAlgorithm.SHA384, "sha-384");
			stdMicAlgs.put(CMSAlgorithm.SHA512, "sha-512");
			stdMicAlgs.put(CMSAlgorithm.GOST3411, "gostr3411-94");
			stdMicAlgs.put(CMSAlgorithm.GOST3411_2012_256, "gostr3411-2012-256");
			stdMicAlgs.put(CMSAlgorithm.GOST3411_2012_512, "gostr3411-2012-512");

			RFC5751_MICALGS = Collections.unmodifiableMap(stdMicAlgs);

			Map oldMicAlgs = new HashMap();

			oldMicAlgs.put(CMSAlgorithm.MD5, "md5");
			oldMicAlgs.put(CMSAlgorithm.SHA1, "sha1");
			oldMicAlgs.put(CMSAlgorithm.SHA224, "sha224");
			oldMicAlgs.put(CMSAlgorithm.SHA256, "sha256");
			oldMicAlgs.put(CMSAlgorithm.SHA384, "sha384");
			oldMicAlgs.put(CMSAlgorithm.SHA512, "sha512");
			oldMicAlgs.put(CMSAlgorithm.GOST3411, "gostr3411-94");
			oldMicAlgs.put(CMSAlgorithm.GOST3411_2012_256, "gostr3411-2012-256");
			oldMicAlgs.put(CMSAlgorithm.GOST3411_2012_512, "gostr3411-2012-512");


			RFC3851_MICALGS = Collections.unmodifiableMap(oldMicAlgs);

			STANDARD_MICALGS = RFC5751_MICALGS;


			Map<string, ASN1ObjectIdentifier> mic = new TreeMap<string, ASN1ObjectIdentifier>(string.CASE_INSENSITIVE_ORDER);

			for (Iterator it = STANDARD_MICALGS.keySet().iterator(); it.hasNext();)
			{
				object key = it.next();
				mic.put(STANDARD_MICALGS.get(key).ToString(), (ASN1ObjectIdentifier)key);
			}

			for (Iterator it = RFC3851_MICALGS.keySet().iterator(); it.hasNext();)
			{
				object key = it.next();
				mic.put(RFC3851_MICALGS.get(key).ToString(), (ASN1ObjectIdentifier)key);
			}

			forMic = Collections.unmodifiableMap(mic);

		}

		internal static string lessQuotes(string @in)
		{
			if (string.ReferenceEquals(@in, null) || @in.Length <= 1) // make sure we have at least 2 characters
			{
				return @in;
			}

			if (@in[0] == '"' && @in[@in.Length - 1] == '"')
			{
				return @in.Substring(1, (@in.Length - 1) - 1);
			}

			return @in;
		}

		internal static string getParameter(string startsWith, List<string> parameters)
		{
			for (Iterator<string> paramIt = parameters.iterator(); paramIt.hasNext();)
			{
				string param = (string)paramIt.next();
				if (param.StartsWith(startsWith, StringComparison.Ordinal))
				{
					return param;
				}
			}

			return null;
		}

		internal static ASN1ObjectIdentifier getDigestOID(string alg)
		{
			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)forMic.get(Strings.toLowerCase(alg));

			if (oid == null)
			{
				throw new IllegalArgumentException("unknown micalg passed: " + alg);
			}

			return oid;
		}

		internal static OutputStream createUnclosable(OutputStream destination)
		{
			return new FilterOutputStreamAnonymousInnerClass(destination);
		}

		public class FilterOutputStreamAnonymousInnerClass : FilterOutputStream
		{
			public FilterOutputStreamAnonymousInnerClass(OutputStream destination) : base(destination)
			{
			}

			public void close()
			{

			}
		}
	}

}
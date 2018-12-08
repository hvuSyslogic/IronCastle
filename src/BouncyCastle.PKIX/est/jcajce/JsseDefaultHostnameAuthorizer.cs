using System;

namespace org.bouncycastle.est.jcajce
{

	using AttributeTypeAndValue = org.bouncycastle.asn1.x500.AttributeTypeAndValue;
	using RDN = org.bouncycastle.asn1.x500.RDN;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using BCStyle = org.bouncycastle.asn1.x500.style.BCStyle;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;


	/// <summary>
	/// A typical hostname authorizer for verifying a hostname against the available certificates.
	/// </summary>
	public class JsseDefaultHostnameAuthorizer : JsseHostnameAuthorizer
	{
		private static Logger LOG = Logger.getLogger(typeof(JsseDefaultHostnameAuthorizer).getName());

		private readonly Set<string> knownSuffixes;

		/// <summary>
		/// Base constructor.
		/// <para>
		/// The authorizer attempts to perform matching (including the use of the wildcard) in accordance with RFC 6125.
		/// </para>
		/// <para>
		/// Known suffixes is a list of public domain suffixes that can't be used as wild cards for
		/// example *.com, or c*c.com, as a dns wildcard could match every/most .com domains if a registrar were issue it.
		/// If *.com is in the known suffixes list will not be allowed to match.
		/// </para>
		/// </summary>
		/// <param name="knownSuffixes"> a set of suffixes that cannot be wild-carded, e.g. { ".com", ".net", ".org" } </param>
		public JsseDefaultHostnameAuthorizer(Set<string> knownSuffixes)
		{
			this.knownSuffixes = knownSuffixes;
		}

		public virtual bool verified(string name, SSLSession context)
		{

			try
			{
				CertificateFactory fac = CertificateFactory.getInstance("X509");
				X509Certificate cert = (X509Certificate)fac.generateCertificate(new ByteArrayInputStream((context.getPeerCertificates()[0]).getEncoded()));

				return verify(name, cert);
			}
			catch (Exception ex)
			{
				if (ex is ESTException)
				{
					throw (ESTException)ex;
				}
				throw new ESTException(ex.Message, ex);
			}
		}

		public virtual bool verify(string name, X509Certificate cert)
		{
			//
			// Test against san.
			//
			try
			{
				Collection n = cert.getSubjectAlternativeNames();
				if (n != null)
				{
					for (Iterator it = n.iterator(); it.hasNext();)
					{
						List l = (List)it.next();
						int type = ((Number)l.get(0)).intValue();
						switch (type)
						{
						case 2:
							if (isValidNameMatch(name, l.get(1).ToString(), knownSuffixes))
							{
								return true;
							}
							break;
						case 7:
							if (InetAddress.getByName(name).Equals(InetAddress.getByName(l.get(1).ToString())))
							{
								return true;
							}
							break;
						default:
							// ignore, maybe log
							if (LOG.isLoggable(Level.INFO))
							{
								string value;
								if (l.get(1) is byte[])
								{
									value = Hex.toHexString((byte[])l.get(1));
								}
								else
								{
									value = l.get(1).ToString();
								}

								LOG.log(Level.INFO, "ignoring type " + type + " value = " + value);
							}
						break;
						}
					}

					//
					// As we had subject alternative names, we must not attempt to match against the CN.
					//

					return false;
				}
			}
			catch (Exception ex)
			{
				throw new ESTException(ex.Message, ex);
			}

			// can't match - would need to check subjectAltName
			if (cert.getSubjectX500Principal() == null)
			{
				return false;
			}

			// Common Name match only.
			RDN[] rdNs = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded()).getRDNs();
			for (int i = 0; i != rdNs.Length; i++)
			{
				RDN rdn = rdNs[i];
				AttributeTypeAndValue[] typesAndValues = rdn.getTypesAndValues();
				for (int j = 0; j != typesAndValues.Length; j++)
				{
					AttributeTypeAndValue atv = typesAndValues[j];
					if (atv.getType().Equals(BCStyle.CN))
					{
						return isValidNameMatch(name, rdn.getFirst().getValue().ToString(), knownSuffixes);
					}
				}
			}
			return false;
		}


		public static bool isValidNameMatch(string name, string dnsName, Set<string> suffixes)
		{

			//
			// Wild card matching.
			//
			if (dnsName.Contains("*"))
			{
				// Only one astrix 
				int wildIndex = dnsName.IndexOf('*');
				if (wildIndex == dnsName.LastIndexOf("*", StringComparison.Ordinal))
				{
					if (dnsName.Contains("..") || dnsName[dnsName.Length - 1] == '*')
					{
						return false;
					}

					int dnsDotIndex = dnsName.IndexOf('.', wildIndex);

					if (suffixes != null && suffixes.contains(Strings.toLowerCase(dnsName.Substring(dnsDotIndex))))
					{
						throw new IOException("Wildcard `" + dnsName + "` matches known public suffix.");
					}

					string end = Strings.toLowerCase(dnsName.Substring(wildIndex + 1));
					string loweredName = Strings.toLowerCase(name);

					if (loweredName.Equals(end))
					{
						return false; // Must not match wild card exactly there must content to the left of the wildcard.
					}

					if (end.Length > loweredName.Length)
					{
						return false;
					}

					if (wildIndex > 0)
					{
						if (loweredName.StartsWith(dnsName.Substring(0, wildIndex), StringComparison.Ordinal) && loweredName.EndsWith(end, StringComparison.Ordinal))
						{
							return loweredName.Substring(wildIndex, (loweredName.Length - end.Length) - wildIndex).IndexOf('.') < 0;
						}
						else
						{
							return false;
						}
					}

					// Must be only one '*' and it must be at position 0.
					string prefix = loweredName.Substring(0, loweredName.Length - end.Length);
					if (prefix.IndexOf('.') > 0)
					{
						return false;
					}

					return loweredName.EndsWith(end, StringComparison.Ordinal);
				}

				return false;
			}

			//
			// No wild card full equality but ignore case.
			//
			return name.Equals(dnsName, StringComparison.OrdinalIgnoreCase);
		}
	}

}
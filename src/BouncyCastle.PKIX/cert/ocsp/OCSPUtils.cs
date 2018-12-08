using System;

namespace org.bouncycastle.cert.ocsp
{

	using ASN1GeneralizedTime = org.bouncycastle.asn1.ASN1GeneralizedTime;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;

	public class OCSPUtils
	{
		internal static readonly X509CertificateHolder[] EMPTY_CERTS = new X509CertificateHolder[0];

		internal static Set EMPTY_SET = Collections.unmodifiableSet(new HashSet());
		internal static List EMPTY_LIST = Collections.unmodifiableList(new ArrayList());

		internal static DateTime extractDate(ASN1GeneralizedTime time)
		{
			try
			{
				return time.getDate();
			}
			catch (Exception e)
			{
				throw new IllegalStateException("exception processing GeneralizedTime: " + e.Message);
			}
		}

		internal static Set getCriticalExtensionOIDs(Extensions extensions)
		{
			if (extensions == null)
			{
				return EMPTY_SET;
			}

			return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getCriticalExtensionOIDs())));
		}

		internal static Set getNonCriticalExtensionOIDs(Extensions extensions)
		{
			if (extensions == null)
			{
				return EMPTY_SET;
			}

			// TODO: should probably produce a set that imposes correct ordering
			return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getNonCriticalExtensionOIDs())));
		}

		internal static List getExtensionOIDs(Extensions extensions)
		{
			if (extensions == null)
			{
				return EMPTY_LIST;
			}

			return Collections.unmodifiableList(Arrays.asList(extensions.getExtensionOIDs()));
		}
	}

}
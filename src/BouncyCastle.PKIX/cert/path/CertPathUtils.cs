namespace org.bouncycastle.cert.path
{

	public class CertPathUtils
	{
		internal static Set getCriticalExtensionsOIDs(X509CertificateHolder[] certificates)
		{
			Set criticalExtensions = new HashSet();

			for (int i = 0; i != certificates.Length; i++)
			{
				criticalExtensions.addAll(certificates[i].getCriticalExtensionOIDs());
			}

			return criticalExtensions;
		}
	}

}
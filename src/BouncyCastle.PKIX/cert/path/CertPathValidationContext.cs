namespace org.bouncycastle.cert.path
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using Memoable = org.bouncycastle.util.Memoable;

	public class CertPathValidationContext : Memoable
	{
		private Set criticalExtensions;

		private Set handledExtensions = new HashSet();
		private bool endEntity;
		private int index;

		public CertPathValidationContext(Set criticalExtensionsOIDs)
		{
			this.criticalExtensions = criticalExtensionsOIDs;
		}

		public virtual void addHandledExtension(ASN1ObjectIdentifier extensionIdentifier)
		{
			this.handledExtensions.add(extensionIdentifier);
		}

		public virtual void setIsEndEntity(bool isEndEntity)
		{
			this.endEntity = isEndEntity;
		}

		public virtual Set getUnhandledCriticalExtensionOIDs()
		{
			Set rv = new HashSet(criticalExtensions);

			rv.removeAll(handledExtensions);

			return rv;
		}

		/// <summary>
		/// Returns true if the current certificate is the end-entity certificate.
		/// </summary>
		/// <returns> if current cert end-entity, false otherwise. </returns>
		public virtual bool isEndEntity()
		{
			return endEntity;
		}

		public virtual Memoable copy()
		{
			return null; //To change body of implemented methods use File | Settings | File Templates.
		}

		public virtual void reset(Memoable other)
		{
			//To change body of implemented methods use File | Settings | File Templates.
		}
	}

}
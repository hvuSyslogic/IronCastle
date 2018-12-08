using System;

namespace org.bouncycastle.x509
{
	using Selector = org.bouncycastle.util.Selector;

	/// <summary>
	/// This class is an <code>Selector</code> like implementation to select
	/// certificates pairs, which are e.g. used for cross certificates. The set of
	/// criteria is given from two
	/// <seealso cref="org.bouncycastle.x509.X509CertStoreSelector"/>s which must be both
	/// matched.
	/// </summary>
	/// <seealso cref= org.bouncycastle.x509.X509AttributeCertificate </seealso>
	/// <seealso cref= org.bouncycastle.x509.X509Store </seealso>
	public class X509CertPairStoreSelector : Selector
	{

		private X509CertStoreSelector forwardSelector;

		private X509CertStoreSelector reverseSelector;

		private X509CertificatePair certPair;

		public X509CertPairStoreSelector()
		{
		}

		/// <summary>
		/// Returns the certificate pair which is used for testing on equality.
		/// </summary>
		/// <returns> Returns the certificate pair which is checked. </returns>
		public virtual X509CertificatePair getCertPair()
		{
			return certPair;
		}

		/// <summary>
		/// Set the certificate pair which is used for testing on equality.
		/// </summary>
		/// <param name="certPair"> The certPairChecking to set. </param>
		public virtual void setCertPair(X509CertificatePair certPair)
		{
			this.certPair = certPair;
		}

		/// <param name="forwardSelector"> The certificate selector for the forward part in
		///            the pair. </param>
		public virtual void setForwardSelector(X509CertStoreSelector forwardSelector)
		{
			this.forwardSelector = forwardSelector;
		}

		/// <param name="reverseSelector"> The certificate selector for the reverse part in
		///            the pair. </param>
		public virtual void setReverseSelector(X509CertStoreSelector reverseSelector)
		{
			this.reverseSelector = reverseSelector;
		}

		/// <summary>
		/// Returns a clone of this selector.
		/// </summary>
		/// <returns> A clone of this selector. </returns>
		/// <seealso cref= java.lang.Object#clone() </seealso>
		public virtual object clone()
		{
			X509CertPairStoreSelector cln = new X509CertPairStoreSelector();

			cln.certPair = certPair;

			if (forwardSelector != null)
			{
				cln.setForwardSelector((X509CertStoreSelector) forwardSelector.clone());
			}

			if (reverseSelector != null)
			{
				cln.setReverseSelector((X509CertStoreSelector) reverseSelector.clone());
			}

			return cln;
		}

		/// <summary>
		/// Decides if the given certificate pair should be selected. If
		/// <code>obj</code> is not a <seealso cref="X509CertificatePair"/> this method
		/// returns <code>false</code>.
		/// </summary>
		/// <param name="obj"> The <seealso cref="X509CertificatePair"/> which should be tested. </param>
		/// <returns> <code>true</code> if the object matches this selector. </returns>
		public virtual bool match(object obj)
		{
			try
			{
				if (!(obj is X509CertificatePair))
				{
					return false;
				}
				X509CertificatePair pair = (X509CertificatePair)obj;

				if (forwardSelector != null && !forwardSelector.match((object)pair.getForward()))
				{
					return false;
				}

				if (reverseSelector != null && !reverseSelector.match((object)pair.getReverse()))
				{
					return false;
				}

				if (certPair != null)
				{
					return certPair.Equals(obj);
				}

				return true;
			}
			catch (Exception)
			{
				return false;
			}
		}

		/// <summary>
		/// Returns the certicate selector for the forward part.
		/// </summary>
		/// <returns> Returns the certicate selector for the forward part. </returns>
		public virtual X509CertStoreSelector getForwardSelector()
		{
			return forwardSelector;
		}

		/// <summary>
		/// Returns the certicate selector for the reverse part.
		/// </summary>
		/// <returns> Returns the reverse selector for teh reverse part. </returns>
		public virtual X509CertStoreSelector getReverseSelector()
		{
			return reverseSelector;
		}
	}

}
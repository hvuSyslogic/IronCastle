namespace org.bouncycastle.cert.dane
{
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	/// <summary>
	/// Factory class for creating DANEEntry objects.
	/// </summary>
	public class DANEEntryFactory
	{
		private readonly DANEEntrySelectorFactory selectorFactory;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="digestCalculator"> a calculator for the message digest to filter email addresses currently SHA-224. </param>
		public DANEEntryFactory(DigestCalculator digestCalculator)
		{
			this.selectorFactory = new DANEEntrySelectorFactory(digestCalculator);
		}

		/// <summary>
		/// Return a DANEEntry for the passed in email address and certificate.
		/// This method sets the entry's certificate usage field to 3.
		/// </summary>
		/// <param name="emailAddress"> the emails address of interest. </param>
		/// <param name="certificate"> the certificate to be associated with the email address. </param>
		/// <exception cref="DANEException"> in case of issue generating a matching name. </exception>
		public virtual DANEEntry createEntry(string emailAddress, X509CertificateHolder certificate)
		{
			return createEntry(emailAddress, DANEEntry.CERT_USAGE_ACCEPT, certificate);
		}

		/// <summary>
		/// Return a DANEEntry for the passed in email address and certificate.
		/// </summary>
		/// <param name="emailAddress"> the emails address of interest. </param>
		/// <param name="certUsage"> the certificate usage field value to use. </param>
		/// <param name="certificate"> the certificate to be associated with the email address. </param>
		/// <exception cref="DANEException"> in case of issue generating a matching name. </exception>
		public virtual DANEEntry createEntry(string emailAddress, int certUsage, X509CertificateHolder certificate)
		{
			if (certUsage < 0 || certUsage > 3)
			{
				throw new DANEException("unknown certificate usage: " + certUsage);
			}

			DANEEntrySelector entrySelector = selectorFactory.createSelector(emailAddress);
			byte[] flags = new byte[3];

			flags[DANEEntry.CERT_USAGE] = (byte)certUsage;
			flags[DANEEntry.SELECTOR] = 0;
			flags[DANEEntry.MATCHING_TYPE] = 0;

			return new DANEEntry(entrySelector.getDomainName(), flags, certificate);
		}
	}

}
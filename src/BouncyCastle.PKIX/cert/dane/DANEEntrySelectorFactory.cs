namespace org.bouncycastle.cert.dane
{

	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// Factory for creating selector objects to use with the DANECertificateStore.
	/// </summary>
	public class DANEEntrySelectorFactory
	{
		private readonly DigestCalculator digestCalculator;

		/// <summary>
		/// Base constructor.
		/// <para>
		/// At the moment you would call this as:
		/// <pre>
		///     new DANEEntrySelectorFactory(new TruncatingDigestCalculator(new SHA256DigestCalculator()));
		/// </pre>
		/// or some equivalent.
		/// 
		/// </para>
		/// </summary>
		/// <param name="digestCalculator"> a calculator for the message digest to filter email addresses currently truncated SHA-256 (originally SHA-224). </param>
		public DANEEntrySelectorFactory(DigestCalculator digestCalculator)
		{
			this.digestCalculator = digestCalculator;
		}

		/// <summary>
		/// Create a selector for the passed in email address. </summary>
		/// <param name="emailAddress"> the emails address of interest. </param>
		/// <exception cref="DANEException"> in case of issue generating a matching name. </exception>
		public virtual DANEEntrySelector createSelector(string emailAddress)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] enc = org.bouncycastle.util.Strings.toUTF8ByteArray(emailAddress.substring(0, emailAddress.indexOf('@')));
			byte[] enc = Strings.toUTF8ByteArray(emailAddress.Substring(0, emailAddress.IndexOf('@')));

			try
			{
				OutputStream cOut = digestCalculator.getOutputStream();

				cOut.write(enc);

				cOut.close();
			}
			catch (IOException e)
			{
				throw new DANEException("Unable to calculate digest string: " + e.Message, e);
			}

			byte[] hash = digestCalculator.getDigest();

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final String domainName = org.bouncycastle.util.Strings.fromByteArray(org.bouncycastle.util.encoders.Hex.encode(hash)) + "._smimecert." + emailAddress.substring(emailAddress.indexOf('@') + 1);
			string domainName = Strings.fromByteArray(Hex.encode(hash)) + "._smimecert." + emailAddress.Substring(emailAddress.IndexOf('@') + 1);

			return new DANEEntrySelector(domainName);
		}
	}

}
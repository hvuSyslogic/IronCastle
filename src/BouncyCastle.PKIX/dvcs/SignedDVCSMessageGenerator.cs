using org.bouncycastle.asn1;

namespace org.bouncycastle.dvcs
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSProcessableByteArray = org.bouncycastle.cms.CMSProcessableByteArray;
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;
	using CMSSignedDataGenerator = org.bouncycastle.cms.CMSSignedDataGenerator;

	public class SignedDVCSMessageGenerator
	{
		private readonly CMSSignedDataGenerator signedDataGen;

		public SignedDVCSMessageGenerator(CMSSignedDataGenerator signedDataGen)
		{
			this.signedDataGen = signedDataGen;
		}

		/// <summary>
		/// Creates a CMSSignedData object containing the passed in DVCSMessage
		/// </summary>
		/// <param name="message"> the request to be signed. </param>
		/// <returns> an encapsulating SignedData object. </returns>
		/// <exception cref="DVCSException"> in the event of failure to encode the request or sign it. </exception>
		public virtual CMSSignedData build(DVCSMessage message)
		{
			try
			{
				byte[] encapsulatedData = message.getContent().toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER);

				return signedDataGen.generate(new CMSProcessableByteArray(message.getContentType(), encapsulatedData), true);
			}
			catch (CMSException e)
			{
				throw new DVCSException("Could not sign DVCS request", e);
			}
			catch (IOException e)
			{
				throw new DVCSException("Could not encode DVCS request", e);
			}
		}
	}

}
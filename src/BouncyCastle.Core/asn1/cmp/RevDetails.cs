using org.bouncycastle.asn1.crmf;
using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.cmp
{
			
	public class RevDetails : ASN1Object
	{
		private CertTemplate certDetails;
		private Extensions crlEntryDetails;

		private RevDetails(ASN1Sequence seq)
		{
			certDetails = CertTemplate.getInstance(seq.getObjectAt(0));
			if (seq.size() > 1)
			{
				crlEntryDetails = Extensions.getInstance(seq.getObjectAt(1));
			}
		}

		public static RevDetails getInstance(object o)
		{
			if (o is RevDetails)
			{
				return (RevDetails)o;
			}

			if (o != null)
			{
				return new RevDetails(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public RevDetails(CertTemplate certDetails)
		{
			this.certDetails = certDetails;
		}

		/// @deprecated use method taking Extensions 
		/// <param name="certDetails"> </param>
		/// <param name="crlEntryDetails"> </param>
		public RevDetails(CertTemplate certDetails, X509Extensions crlEntryDetails)
		{
			this.certDetails = certDetails;
			this.crlEntryDetails = Extensions.getInstance(crlEntryDetails.toASN1Primitive());
		}

		public RevDetails(CertTemplate certDetails, Extensions crlEntryDetails)
		{
			this.certDetails = certDetails;
			this.crlEntryDetails = crlEntryDetails;
		}

		public virtual CertTemplate getCertDetails()
		{
			return certDetails;
		}

		public virtual Extensions getCrlEntryDetails()
		{
			return crlEntryDetails;
		}

		/// <summary>
		/// <pre>
		/// RevDetails ::= SEQUENCE {
		///                  certDetails         CertTemplate,
		///                   -- allows requester to specify as much as they can about
		///                   -- the cert. for which revocation is requested
		///                   -- (e.g., for cases in which serialNumber is not available)
		///                   crlEntryDetails     Extensions       OPTIONAL
		///                   -- requested crlEntryExtensions
		///             }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certDetails);

			if (crlEntryDetails != null)
			{
				v.add(crlEntryDetails);
			}

			return new DERSequence(v);
		}
	}

}
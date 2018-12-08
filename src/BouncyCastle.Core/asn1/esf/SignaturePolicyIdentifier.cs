using org.bouncycastle.asn1;

namespace org.bouncycastle.asn1.esf
{

	public class SignaturePolicyIdentifier : ASN1Object
	{
		private SignaturePolicyId signaturePolicyId;
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		private bool isSignaturePolicyImplied_Renamed;

		public static SignaturePolicyIdentifier getInstance(object obj)
		{
			if (obj is SignaturePolicyIdentifier)
			{
				return (SignaturePolicyIdentifier)obj;
			}
			else if (obj is ASN1Null || hasEncodedTagValue(obj, BERTags_Fields.NULL))
			{
				return new SignaturePolicyIdentifier();
			}
			else if (obj != null)
			{
				return new SignaturePolicyIdentifier(SignaturePolicyId.getInstance(obj));
			}

			return null;
		}

		public SignaturePolicyIdentifier()
		{
			this.isSignaturePolicyImplied_Renamed = true;
		}

		public SignaturePolicyIdentifier(SignaturePolicyId signaturePolicyId)
		{
			this.signaturePolicyId = signaturePolicyId;
			this.isSignaturePolicyImplied_Renamed = false;
		}

		public virtual SignaturePolicyId getSignaturePolicyId()
		{
			return signaturePolicyId;
		}

		public virtual bool isSignaturePolicyImplied()
		{
			return isSignaturePolicyImplied_Renamed;
		}

		/// <summary>
		/// <pre>
		/// SignaturePolicyIdentifier ::= CHOICE{
		///     SignaturePolicyId         SignaturePolicyId,
		///     SignaturePolicyImplied    SignaturePolicyImplied }
		/// 
		/// SignaturePolicyImplied ::= NULL
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			if (isSignaturePolicyImplied_Renamed)
			{
				return DERNull.INSTANCE;
			}
			else
			{
				return signaturePolicyId.toASN1Primitive();
			}
		}
	}

}
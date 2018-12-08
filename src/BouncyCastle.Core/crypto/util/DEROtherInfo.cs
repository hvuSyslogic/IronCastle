namespace org.bouncycastle.crypto.util
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1TaggedObject = org.bouncycastle.asn1.ASN1TaggedObject;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// Builder and holder class for preparing SP 800-56A compliant OtherInfo. The data is ultimately encoded as a DER SEQUENCE.
	/// Empty octet strings are used to represent nulls in compulsory fields.
	/// </summary>
	public class DEROtherInfo
	{
		/// <summary>
		/// Builder to create OtherInfo
		/// </summary>
		public sealed class Builder
		{
			internal readonly AlgorithmIdentifier algorithmID;
			internal readonly ASN1OctetString partyUVInfo;
			internal readonly ASN1OctetString partyVInfo;

			internal ASN1TaggedObject suppPubInfo;
			internal ASN1TaggedObject suppPrivInfo;

			/// <summary>
			/// Create a basic builder with just the compulsory fields.
			/// </summary>
			/// <param name="algorithmID"> the algorithm associated with this invocation of the KDF. </param>
			/// <param name="partyUInfo">  sender party info. </param>
			/// <param name="partyVInfo">  receiver party info. </param>
			public Builder(AlgorithmIdentifier algorithmID, byte[] partyUInfo, byte[] partyVInfo)
			{
				this.algorithmID = algorithmID;
				this.partyUVInfo = DerUtil.getOctetString(partyUInfo);
				this.partyVInfo = DerUtil.getOctetString(partyVInfo);
			}

			/// <summary>
			/// Add optional supplementary public info (DER tagged, implicit, 0).
			/// </summary>
			/// <param name="suppPubInfo"> supplementary public info. </param>
			/// <returns>  the current builder instance. </returns>
			public Builder withSuppPubInfo(byte[] suppPubInfo)
			{
				this.suppPubInfo = new DERTaggedObject(false, 0, DerUtil.getOctetString(suppPubInfo));

				return this;
			}

			/// <summary>
			/// Add optional supplementary private info (DER tagged, implicit, 1).
			/// </summary>
			/// <param name="suppPrivInfo"> supplementary private info. </param>
			/// <returns> the current builder instance. </returns>
			public Builder withSuppPrivInfo(byte[] suppPrivInfo)
			{
				this.suppPrivInfo = new DERTaggedObject(false, 1, DerUtil.getOctetString(suppPrivInfo));

				return this;
			}

			/// <summary>
			/// Build the KTSOtherInfo.
			/// </summary>
			/// <returns> an KTSOtherInfo containing the data. </returns>
			public DEROtherInfo build()
			{
				ASN1EncodableVector v = new ASN1EncodableVector();

				v.add(algorithmID);
				v.add(partyUVInfo);
				v.add(partyVInfo);

				if (suppPubInfo != null)
				{
					v.add(suppPubInfo);
				}

				if (suppPrivInfo != null)
				{
					v.add(suppPrivInfo);
				}

				return new DEROtherInfo(new DERSequence(v));
			}
		}

		private readonly DERSequence sequence;

		private DEROtherInfo(DERSequence sequence)
		{
			this.sequence = sequence;
		}

		public virtual byte[] getEncoded()
		{
			return sequence.getEncoded();
		}
	}

}
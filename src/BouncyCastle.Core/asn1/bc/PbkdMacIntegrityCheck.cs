namespace org.bouncycastle.asn1.bc
{
	using KeyDerivationFunc = org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// <pre>
	/// PbkdMacIntegrityCheck ::= SEQUENCE {
	///     macAlgorithm AlgorithmIdentifier,
	///     pbkdAlgorithm KeyDerivationFunc,
	///     mac OCTET STRING
	/// }
	/// </pre>
	/// </summary>
	public class PbkdMacIntegrityCheck : ASN1Object
	{
		private readonly AlgorithmIdentifier macAlgorithm;
		private readonly KeyDerivationFunc pbkdAlgorithm;
		private readonly ASN1OctetString mac;

		public PbkdMacIntegrityCheck(AlgorithmIdentifier macAlgorithm, KeyDerivationFunc pbkdAlgorithm, byte[] mac)
		{
			this.macAlgorithm = macAlgorithm;
			this.pbkdAlgorithm = pbkdAlgorithm;
			this.mac = new DEROctetString(Arrays.clone(mac));
		}

		private PbkdMacIntegrityCheck(ASN1Sequence seq)
		{
			this.macAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			this.pbkdAlgorithm = KeyDerivationFunc.getInstance(seq.getObjectAt(1));
			this.mac = ASN1OctetString.getInstance(seq.getObjectAt(2));
		}

		public static PbkdMacIntegrityCheck getInstance(object o)
		{
			if (o is PbkdMacIntegrityCheck)
			{
				return (PbkdMacIntegrityCheck)o;
			}
			else if (o != null)
			{
				return new PbkdMacIntegrityCheck(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual AlgorithmIdentifier getMacAlgorithm()
		{
			return macAlgorithm;
		}

		public virtual KeyDerivationFunc getPbkdAlgorithm()
		{
			return pbkdAlgorithm;
		}

		public virtual byte[] getMac()
		{
			return Arrays.clone(mac.getOctets());
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(macAlgorithm);
			v.add(pbkdAlgorithm);
			v.add(mac);

			return new DERSequence(v);
		}
	}

}
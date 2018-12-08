namespace org.bouncycastle.bcpg
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// base class for an ECDH Public Key.
	/// </summary>
	public class ECDHPublicBCPGKey : ECPublicBCPGKey
	{
		private byte reserved;
		private byte hashFunctionId;
		private byte symAlgorithmId;

		/// <param name="in"> the stream to read the packet from. </param>
		public ECDHPublicBCPGKey(BCPGInputStream @in) : base(@in)
		{

			int length = @in.read();
			byte[] kdfParameters = new byte[length];
			if (kdfParameters.Length != 3)
			{
				throw new IllegalStateException("kdf parameters size of 3 expected.");
			}

			@in.readFully(kdfParameters);

			reserved = kdfParameters[0];
			hashFunctionId = kdfParameters[1];
			symAlgorithmId = kdfParameters[2];

			verifyHashAlgorithm();
			verifySymmetricKeyAlgorithm();
		}

		public ECDHPublicBCPGKey(ASN1ObjectIdentifier oid, ECPoint point, int hashAlgorithm, int symmetricKeyAlgorithm) : base(oid, point)
		{

			reserved = 1;
			hashFunctionId = (byte)hashAlgorithm;
			symAlgorithmId = (byte)symmetricKeyAlgorithm;

			verifyHashAlgorithm();
			verifySymmetricKeyAlgorithm();
		}

		public virtual byte getReserved()
		{
			return reserved;
		}

		public virtual byte getHashAlgorithm()
		{
			return hashFunctionId;
		}

		public virtual byte getSymmetricKeyAlgorithm()
		{
			return symAlgorithmId;
		}

		public override void encode(BCPGOutputStream @out)
		{
			base.encode(@out);
			@out.write(0x3);
			@out.write(reserved);
			@out.write(hashFunctionId);
			@out.write(symAlgorithmId);
		}

		private void verifyHashAlgorithm()
		{
			switch (hashFunctionId)
			{
			case HashAlgorithmTags_Fields.SHA256:
			case HashAlgorithmTags_Fields.SHA384:
			case HashAlgorithmTags_Fields.SHA512:
				break;

			default:
				throw new IllegalStateException("Hash algorithm must be SHA-256 or stronger.");
			}
		}

		private void verifySymmetricKeyAlgorithm()
		{
			switch (symAlgorithmId)
			{
			case SymmetricKeyAlgorithmTags_Fields.AES_128:
			case SymmetricKeyAlgorithmTags_Fields.AES_192:
			case SymmetricKeyAlgorithmTags_Fields.AES_256:
				break;

			default:
				throw new IllegalStateException("Symmetric key algorithm must be AES-128 or stronger.");
			}
		}
	}

}
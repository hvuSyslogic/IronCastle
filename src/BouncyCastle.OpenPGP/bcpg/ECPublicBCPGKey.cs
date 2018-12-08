namespace org.bouncycastle.bcpg
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// base class for an EC Public Key.
	/// </summary>
	public abstract class ECPublicBCPGKey : BCPGObject, BCPGKey
	{
		internal ASN1ObjectIdentifier oid;
		internal BigInteger point;

		/// <param name="in"> the stream to read the packet from. </param>
		public ECPublicBCPGKey(BCPGInputStream @in)
		{
			this.oid = ASN1ObjectIdentifier.getInstance(ASN1Primitive.fromByteArray(readBytesOfEncodedLength(@in)));
			this.point = (new MPInteger(@in)).getValue();
		}

		public ECPublicBCPGKey(ASN1ObjectIdentifier oid, ECPoint point)
		{
			this.point = new BigInteger(1, point.getEncoded(false));
			this.oid = oid;
		}

		public ECPublicBCPGKey(ASN1ObjectIdentifier oid, BigInteger encodedPoint)
		{
			this.point = encodedPoint;
			this.oid = oid;
		}

		/// <summary>
		/// return "PGP"
		/// </summary>
		/// <seealso cref= org.bouncycastle.bcpg.BCPGKey#getFormat() </seealso>
		public virtual string getFormat()
		{
			return "PGP";
		}

		/// <summary>
		/// return the standard PGP encoding of the key.
		/// </summary>
		/// <seealso cref= org.bouncycastle.bcpg.BCPGKey#getEncoded() </seealso>
		public override byte[] getEncoded()
		{
			try
			{
				return base.getEncoded();
			}
			catch (IOException)
			{
				return null;
			}
		}

		public override void encode(BCPGOutputStream @out)
		{
			byte[] oid = this.oid.getEncoded();
			@out.write(oid, 1, oid.Length - 1);

			MPInteger point = new MPInteger(this.point);
			@out.writeObject(point);
		}

		/// <returns> point </returns>
		public virtual BigInteger getEncodedPoint()
		{
			return point;
		}

		/// <returns> oid </returns>
		public virtual ASN1ObjectIdentifier getCurveOID()
		{
			return oid;
		}

		protected internal static byte[] readBytesOfEncodedLength(BCPGInputStream @in)
		{
			int length = @in.read();
			if (length == 0 || length == 0xFF)
			{
				throw new IOException("future extensions not yet implemented.");
			}

			byte[] buffer = new byte[length + 2];
			@in.readFully(buffer, 2, buffer.Length - 2);
			buffer[0] = (byte)0x06;
			buffer[1] = (byte)length;

			return buffer;
		}
	}

}
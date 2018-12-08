namespace org.bouncycastle.asn1.x9
{
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Class for describing an ECPoint as a DER object.
	/// </summary>
	public class X9ECPoint : ASN1Object
	{
		private readonly ASN1OctetString encoding;

		private ECCurve c;
		private ECPoint p;

		public X9ECPoint(ECPoint p) : this(p, false)
		{
		}

		public X9ECPoint(ECPoint p, bool compressed)
		{
			this.p = p.normalize();
			this.encoding = new DEROctetString(p.getEncoded(compressed));
		}

		public X9ECPoint(ECCurve c, byte[] encoding)
		{
			this.c = c;
			this.encoding = new DEROctetString(Arrays.clone(encoding));
		}

		public X9ECPoint(ECCurve c, ASN1OctetString s) : this(c, s.getOctets())
		{
		}

		public virtual byte[] getPointEncoding()
		{
			return Arrays.clone(encoding.getOctets());
		}

		public virtual ECPoint getPoint()
		{
			lock (this)
			{
				if (p == null)
				{
					p = c.decodePoint(encoding.getOctets()).normalize();
				}
        
				return p;
			}
		}

		public virtual bool isPointCompressed()
		{
			byte[] octets = encoding.getOctets();
			return octets != null && octets.Length > 0 && (octets[0] == 2 || octets[0] == 3);
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		///  ECPoint ::= OCTET STRING
		/// </pre>
		/// <para>
		/// Octet string produced using ECPoint.getEncoded().
		/// </para>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return encoding;
		}
	}

}
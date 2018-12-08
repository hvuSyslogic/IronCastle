using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x9
{


	/// <summary>
	/// X9.44 Diffie-Hellman domain parameters.
	/// <pre>
	///    DomainParameters ::= SEQUENCE {
	///       p                INTEGER,           -- odd prime, p=jq +1
	///       g                INTEGER,           -- generator, g
	///       q                INTEGER,           -- factor of p-1
	///       j                INTEGER OPTIONAL,  -- subgroup factor, j &gt;= 2
	///       validationParams  ValidationParams OPTIONAL
	///    }
	/// </pre>
	/// </summary>
	public class DomainParameters : ASN1Object
	{
		private readonly ASN1Integer p, g, q, j;
		private readonly ValidationParams validationParams;

		/// <summary>
		/// Return a DomainParameters object from the passed in tagged object.
		/// </summary>
		/// <param name="obj"> a tagged object. </param>
		/// <param name="explicit"> true if the contents of the object is explictly tagged, false otherwise. </param>
		/// <returns> a DomainParameters </returns>
		public static DomainParameters getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return a DomainParameters object from the passed in object.
		/// </summary>
		/// <param name="obj"> an object for conversion or a byte[]. </param>
		/// <returns> a DomainParameters </returns>
		public static DomainParameters getInstance(object obj)
		{
			if (obj is DomainParameters)
			{
				return (DomainParameters)obj;
			}
			else if (obj != null)
			{
				return new DomainParameters(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Base constructor - the full domain parameter set.
		/// </summary>
		/// <param name="p"> the prime p defining the Galois field. </param>
		/// <param name="g"> the generator of the multiplicative subgroup of order g. </param>
		/// <param name="q"> specifies the prime factor of p - 1 </param>
		/// <param name="j"> optionally specifies the value that satisfies the equation p = jq+1 </param>
		/// <param name="validationParams"> parameters for validating these domain parameters. </param>
		public DomainParameters(BigInteger p, BigInteger g, BigInteger q, BigInteger j, ValidationParams validationParams)
		{
			if (p == null)
			{
				throw new IllegalArgumentException("'p' cannot be null");
			}
			if (g == null)
			{
				throw new IllegalArgumentException("'g' cannot be null");
			}
			if (q == null)
			{
				throw new IllegalArgumentException("'q' cannot be null");
			}

			this.p = new ASN1Integer(p);
			this.g = new ASN1Integer(g);
			this.q = new ASN1Integer(q);

			if (j != null)
			{
				this.j = new ASN1Integer(j);
			}
			else
			{
				this.j = null;
			}
			this.validationParams = validationParams;
		}

		private DomainParameters(ASN1Sequence seq)
		{
			if (seq.size() < 3 || seq.size() > 5)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			Enumeration e = seq.getObjects();
			this.p = ASN1Integer.getInstance(e.nextElement());
			this.g = ASN1Integer.getInstance(e.nextElement());
			this.q = ASN1Integer.getInstance(e.nextElement());

			ASN1Encodable next = getNext(e);

			if (next != null && next is ASN1Integer)
			{
				this.j = ASN1Integer.getInstance(next);
				next = getNext(e);
			}
			else
			{
				this.j = null;
			}

			if (next != null)
			{
				this.validationParams = ValidationParams.getInstance(next.toASN1Primitive());
			}
			else
			{
				this.validationParams = null;
			}
		}

		private static ASN1Encodable getNext(Enumeration e)
		{
			return e.hasMoreElements() ? (ASN1Encodable)e.nextElement() : null;
		}

		/// <summary>
		/// Return the prime p defining the Galois field.
		/// </summary>
		/// <returns> the prime p. </returns>
		public virtual BigInteger getP()
		{
			return this.p.getPositiveValue();
		}

		/// <summary>
		/// Return the generator of the multiplicative subgroup of order g.
		/// </summary>
		/// <returns> the generator g. </returns>
		public virtual BigInteger getG()
		{
			return this.g.getPositiveValue();
		}

		/// <summary>
		/// Return q, the prime factor of p - 1
		/// </summary>
		/// <returns> q value </returns>
		public virtual BigInteger getQ()
		{
			return this.q.getPositiveValue();
		}

		/// <summary>
		/// Return the value that satisfies the equation p = jq+1 (if present).
		/// </summary>
		/// <returns> j value or null. </returns>
		public virtual BigInteger getJ()
		{
			if (this.j == null)
			{
				return null;
			}

			return this.j.getPositiveValue();
		}

		/// <summary>
		/// Return the validation parameters for this set (if present).
		/// </summary>
		/// <returns> validation parameters, or null if absent. </returns>
		public virtual ValidationParams getValidationParams()
		{
			return this.validationParams;
		}

		/// <summary>
		/// Return an ASN.1 primitive representation of this object.
		/// </summary>
		/// <returns> a DERSequence containing the parameter values. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(this.p);
			v.add(this.g);
			v.add(this.q);

			if (this.j != null)
			{
				v.add(this.j);
			}

			if (this.validationParams != null)
			{
				v.add(this.validationParams);
			}

			return new DERSequence(v);
		}
	}
}
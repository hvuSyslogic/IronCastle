using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{


	public class BasicConstraints : ASN1Object
	{
		internal ASN1Boolean cA = ASN1Boolean.getInstance(false);
		internal ASN1Integer pathLenConstraint = null;

		public static BasicConstraints getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static BasicConstraints getInstance(object obj)
		{
			if (obj is BasicConstraints)
			{
				return (BasicConstraints)obj;
			}
			if (obj is X509Extension)
			{
				return getInstance(X509Extension.convertValueToObject((X509Extension)obj));
			}
			if (obj != null)
			{
				return new BasicConstraints(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static BasicConstraints fromExtensions(Extensions extensions)
		{
			return BasicConstraints.getInstance(extensions.getExtensionParsedValue(Extension.basicConstraints));
		}

		private BasicConstraints(ASN1Sequence seq)
		{
			if (seq.size() == 0)
			{
				this.cA = null;
				this.pathLenConstraint = null;
			}
			else
			{
				if (seq.getObjectAt(0) is ASN1Boolean)
				{
					this.cA = ASN1Boolean.getInstance(seq.getObjectAt(0));
				}
				else
				{
					this.cA = null;
					this.pathLenConstraint = ASN1Integer.getInstance(seq.getObjectAt(0));
				}
				if (seq.size() > 1)
				{
					if (this.cA != null)
					{
						this.pathLenConstraint = ASN1Integer.getInstance(seq.getObjectAt(1));
					}
					else
					{
						throw new IllegalArgumentException("wrong sequence in constructor");
					}
				}
			}
		}

		public BasicConstraints(bool cA)
		{
			if (cA)
			{
				this.cA = ASN1Boolean.getInstance(true);
			}
			else
			{
				this.cA = null;
			}
			this.pathLenConstraint = null;
		}

		/// <summary>
		/// create a cA=true object for the given path length constraint.
		/// </summary>
		/// <param name="pathLenConstraint"> </param>
		public BasicConstraints(int pathLenConstraint)
		{
			this.cA = ASN1Boolean.getInstance(true);
			this.pathLenConstraint = new ASN1Integer(pathLenConstraint);
		}

		public virtual bool isCA()
		{
			return (cA != null) && cA.isTrue();
		}

		public virtual BigInteger getPathLenConstraint()
		{
			if (pathLenConstraint != null)
			{
				return pathLenConstraint.getValue();
			}

			return null;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// BasicConstraints := SEQUENCE {
		///    cA                  BOOLEAN DEFAULT FALSE,
		///    pathLenConstraint   INTEGER (0..MAX) OPTIONAL
		/// }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (cA != null)
			{
				v.add(cA);
			}

			if (pathLenConstraint != null) // yes some people actually do this when cA is false...
			{
				v.add(pathLenConstraint);
			}

			return new DERSequence(v);
		}

		public override string ToString()
		{
			if (pathLenConstraint == null)
			{
				if (cA == null)
				{
					return "BasicConstraints: isCa(false)";
				}
				return "BasicConstraints: isCa(" + this.isCA() + ")";
			}
			return "BasicConstraints: isCa(" + this.isCA() + "), pathLenConstraint = " + pathLenConstraint.getValue();
		}
	}

}
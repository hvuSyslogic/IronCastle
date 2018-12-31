using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.eac
{

	
	/// <summary>
	/// an Iso7816ECDSAPublicKeyStructure structure.
	/// <pre>
	///  Certificate Holder Authorization ::= SEQUENCE {
	///      ASN1TaggedObject primeModulusP;        // OPTIONAL
	///      ASN1TaggedObject firstCoefA;            // OPTIONAL
	///      ASN1TaggedObject secondCoefB;        // OPTIONAL
	///      ASN1TaggedObject basePointG;            // OPTIONAL
	///      ASN1TaggedObject orderOfBasePointR;    // OPTIONAL
	///      ASN1TaggedObject publicPointY;        //REQUIRED
	///      ASN1TaggedObject    cofactorF;            // OPTIONAL
	///  }
	/// </pre>
	/// </summary>
	public class ECDSAPublicKey : PublicKeyDataObject
	{
		private ASN1ObjectIdentifier usage;
		private BigInteger primeModulusP; // OPTIONAL
		private BigInteger firstCoefA; // OPTIONAL
		private BigInteger secondCoefB; // OPTIONAL
		private byte[] basePointG; // OPTIONAL
		private BigInteger orderOfBasePointR; // OPTIONAL
		private byte[] publicPointY; //REQUIRED
		private BigInteger cofactorF; // OPTIONAL
		private int options;
		private const int P = 0x01;
		private const int A = 0x02;
		private const int B = 0x04;
		private const int G = 0x08;
		private const int R = 0x10;
		private const int Y = 0x20;
		private const int F = 0x40;

		public ECDSAPublicKey(ASN1Sequence seq)
		{
			Enumeration en = seq.getObjects();

			this.usage = ASN1ObjectIdentifier.getInstance(en.nextElement());

			options = 0;
			while (en.hasMoreElements())
			{
				object obj = en.nextElement();

				if (obj is ASN1TaggedObject)
				{
					ASN1TaggedObject to = (ASN1TaggedObject)obj;
					switch (to.getTagNo())
					{
					case 0x1:
						setPrimeModulusP(UnsignedInteger.getInstance(to).getValue());
						break;
					case 0x2:
						setFirstCoefA(UnsignedInteger.getInstance(to).getValue());
						break;
					case 0x3:
						setSecondCoefB(UnsignedInteger.getInstance(to).getValue());
						break;
					case 0x4:
						setBasePointG(ASN1OctetString.getInstance(to, false));
						break;
					case 0x5:
						setOrderOfBasePointR(UnsignedInteger.getInstance(to).getValue());
						break;
					case 0x6:
						setPublicPointY(ASN1OctetString.getInstance(to, false));
						break;
					case 0x7:
						setCofactorF(UnsignedInteger.getInstance(to).getValue());
						break;
					default:
						options = 0;
						throw new IllegalArgumentException("Unknown Object Identifier!");
					}
				}
				else
				{
					throw new IllegalArgumentException("Unknown Object Identifier!");
				}
			}
			if (options != 0x20 && options != 0x7F)
			{
				throw new IllegalArgumentException("All options must be either present or absent!");
			}
		}

		public ECDSAPublicKey(ASN1ObjectIdentifier usage, byte[] ppY)
		{
			this.usage = usage;
			setPublicPointY(new DEROctetString(ppY));
		}

		public ECDSAPublicKey(ASN1ObjectIdentifier usage, BigInteger p, BigInteger a, BigInteger b, byte[] basePoint, BigInteger order, byte[] publicPoint, int cofactor)
		{
			this.usage = usage;
			setPrimeModulusP(p);
			setFirstCoefA(a);
			setSecondCoefB(b);
			setBasePointG(new DEROctetString(basePoint));
			setOrderOfBasePointR(order);
			setPublicPointY(new DEROctetString(publicPoint));
			setCofactorF(BigInteger.valueOf(cofactor));
		}

		public override ASN1ObjectIdentifier getUsage()
		{
			return usage;
		}

		public virtual byte[] getBasePointG()
		{
			if ((options & G) != 0)
			{
				return Arrays.clone(basePointG);
			}
			else
			{
				return null;
			}
		}

		private void setBasePointG(ASN1OctetString basePointG)
		{
			if ((options & G) == 0)
			{
				options |= G;
				this.basePointG = basePointG.getOctets();
			}
			else
			{
				throw new IllegalArgumentException("Base Point G already set");
			}
		}

		public virtual BigInteger getCofactorF()
		{
			if ((options & F) != 0)
			{
				return cofactorF;
			}
			else
			{
				return null;
			}
		}

		private void setCofactorF(BigInteger cofactorF)
		{
			if ((options & F) == 0)
			{
				options |= F;
				this.cofactorF = cofactorF;
			}
			else
			{
				throw new IllegalArgumentException("Cofactor F already set");
			}
		}

		public virtual BigInteger getFirstCoefA()
		{
			if ((options & A) != 0)
			{
				return firstCoefA;
			}
			else
			{
				return null;
			}
		}

		private void setFirstCoefA(BigInteger firstCoefA)
		{
			if ((options & A) == 0)
			{
				options |= A;
				this.firstCoefA = firstCoefA;
			}
			else
			{
				throw new IllegalArgumentException("First Coef A already set");
			}
		}

		public virtual BigInteger getOrderOfBasePointR()
		{
			if ((options & R) != 0)
			{
				return orderOfBasePointR;
			}
			else
			{
				return null;
			}
		}

		private void setOrderOfBasePointR(BigInteger orderOfBasePointR)
		{
			if ((options & R) == 0)
			{
				options |= R;
				this.orderOfBasePointR = orderOfBasePointR;
			}
			else
			{
				throw new IllegalArgumentException("Order of base point R already set");
			}
		}

		public virtual BigInteger getPrimeModulusP()
		{
			if ((options & P) != 0)
			{
				return primeModulusP;
			}
			else
			{
				return null;
			}
		}

		private void setPrimeModulusP(BigInteger primeModulusP)
		{
			if ((options & P) == 0)
			{
				options |= P;
				this.primeModulusP = primeModulusP;
			}
			else
			{
				throw new IllegalArgumentException("Prime Modulus P already set");
			}
		}

		public virtual byte[] getPublicPointY()
		{
			if ((options & Y) != 0)
			{
				return Arrays.clone(publicPointY);
			}
			else
			{
				return null;
			}
		}

		private void setPublicPointY(ASN1OctetString publicPointY)
		{
			if ((options & Y) == 0)
			{
				options |= Y;
				this.publicPointY = publicPointY.getOctets();
			}
			else
			{
				throw new IllegalArgumentException("Public Point Y already set");
			}
		}

		public virtual BigInteger getSecondCoefB()
		{
			if ((options & B) != 0)
			{
				return secondCoefB;
			}
			else
			{
				return null;
			}
		}

		private void setSecondCoefB(BigInteger secondCoefB)
		{
			if ((options & B) == 0)
			{
				options |= B;
				this.secondCoefB = secondCoefB;
			}
			else
			{
				throw new IllegalArgumentException("Second Coef B already set");
			}
		}

		public virtual bool hasParameters()
		{
			return primeModulusP != null;
		}

		public virtual ASN1EncodableVector getASN1EncodableVector(ASN1ObjectIdentifier oid, bool publicPointOnly)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(oid);

			if (!publicPointOnly)
			{
				v.add(new UnsignedInteger(0x01, getPrimeModulusP()));
				v.add(new UnsignedInteger(0x02, getFirstCoefA()));
				v.add(new UnsignedInteger(0x03, getSecondCoefB()));
				v.add(new DERTaggedObject(false, 0x04, new DEROctetString(getBasePointG())));
				v.add(new UnsignedInteger(0x05, getOrderOfBasePointR()));
			}
			v.add(new DERTaggedObject(false, 0x06, new DEROctetString(getPublicPointY())));
			if (!publicPointOnly)
			{
				v.add(new UnsignedInteger(0x07, getCofactorF()));
			}

			return v;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(getASN1EncodableVector(usage, !hasParameters()));
		}
	}

}
using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.field
{

	using Integers = org.bouncycastle.util.Integers;

	public class GenericPolynomialExtensionField : PolynomialExtensionField
	{
		protected internal readonly FiniteField subfield;
		protected internal readonly Polynomial minimalPolynomial;

		public GenericPolynomialExtensionField(FiniteField subfield, Polynomial polynomial)
		{
			this.subfield = subfield;
			this.minimalPolynomial = polynomial;
		}

		public virtual BigInteger getCharacteristic()
		{
			return subfield.getCharacteristic();
		}

		public virtual int getDimension()
		{
			return subfield.getDimension() * minimalPolynomial.getDegree();
		}

		public virtual FiniteField getSubfield()
		{
			return subfield;
		}

		public virtual int getDegree()
		{
			return minimalPolynomial.getDegree();
		}

		public virtual Polynomial getMinimalPolynomial()
		{
			return minimalPolynomial;
		}

		public override bool Equals(object obj)
		{
			if (this == obj)
			{
				return true;
			}
			if (!(obj is GenericPolynomialExtensionField))
			{
				return false;
			}
			GenericPolynomialExtensionField other = (GenericPolynomialExtensionField)obj;
			return subfield.Equals(other.subfield) && minimalPolynomial.Equals(other.minimalPolynomial);
		}

		public override int GetHashCode()
		{
			return subfield.GetHashCode() ^ Integers.rotateLeft(minimalPolynomial.GetHashCode(), 16);
		}
	}

}
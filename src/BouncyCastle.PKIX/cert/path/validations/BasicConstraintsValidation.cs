namespace org.bouncycastle.cert.path.validations
{

	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Memoable = org.bouncycastle.util.Memoable;

	public class BasicConstraintsValidation : CertPathValidation
	{
		private bool isMandatory;
		private BasicConstraints bc;
		private int pathLengthRemaining;
		private BigInteger maxPathLength;

		public BasicConstraintsValidation() : this(true)
		{
		}

		public BasicConstraintsValidation(bool isMandatory)
		{
			this.isMandatory = isMandatory;
		}

		public virtual void validate(CertPathValidationContext context, X509CertificateHolder certificate)
		{
			if (maxPathLength != null && pathLengthRemaining < 0)
			{
				throw new CertPathValidationException("BasicConstraints path length exceeded");
			}

			context.addHandledExtension(Extension.basicConstraints);

			BasicConstraints certBC = BasicConstraints.fromExtensions(certificate.getExtensions());

			if (certBC != null)
			{
				if (bc != null)
				{
					if (certBC.isCA())
					{
						BigInteger pathLengthConstraint = certBC.getPathLenConstraint();

						if (pathLengthConstraint != null)
						{
							int plc = pathLengthConstraint.intValue();

							if (plc < pathLengthRemaining)
							{
								pathLengthRemaining = plc;
								bc = certBC;
							}
						}
					}
				}
				else
				{
					bc = certBC;
					if (certBC.isCA())
					{
						maxPathLength = certBC.getPathLenConstraint();

						if (maxPathLength != null)
						{
							pathLengthRemaining = maxPathLength.intValue();
						}
					}
				}
			}
			else
			{
				if (bc != null)
				{
					pathLengthRemaining--;
				}
			}

			if (isMandatory && bc == null)
			{
				throw new CertPathValidationException("BasicConstraints not present in path");
			}
		}

		public virtual Memoable copy()
		{
			BasicConstraintsValidation v = new BasicConstraintsValidation(isMandatory);

			v.bc = this.bc;
			v.pathLengthRemaining = this.pathLengthRemaining;

			return v;
		}

		public virtual void reset(Memoable other)
		{
			BasicConstraintsValidation v = (BasicConstraintsValidation)other;

			this.isMandatory = v.isMandatory;
			this.bc = v.bc;
			this.pathLengthRemaining = v.pathLengthRemaining;
		}
	}

}
namespace org.bouncycastle.jce.provider.test
{
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralSubtree = org.bouncycastle.asn1.x509.GeneralSubtree;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	/// <summary>
	/// Test class for <seealso cref="PKIXNameConstraintValidator"/>.
	/// <para>
	/// The field testXYZ is the name to test.
	/// </para>
	/// <para>
	/// The field testXYZIsConstraint must be tested if it is permitted and excluded.
	/// </para>
	/// <para>
	/// The field testXYZIsNotConstraint must be tested if it is not permitted and
	/// not excluded.
	/// </para>
	/// <para>
	/// Furthermore there are tests for the intersection and union of test names.
	/// 
	/// </para>
	/// </summary>
	public class PKIXNameConstraintsTest : SimpleTest
	{

		private const string testEmail = "test@abc.test.com";

		private static readonly string[] testEmailIsConstraint = new string[] {"test@abc.test.com", "abc.test.com", ".test.com"};

		private static readonly string[] testEmailIsNotConstraint = new string[] {".abc.test.com", "www.test.com", "test1@abc.test.com", "bc.test.com"};

		private static readonly string[] email1 = new string[] {"test@test.com", "test@test.com", "test@test.com", "test@abc.test.com", "test@test.com", "test@test.com", ".test.com", ".test.com", ".test.com", ".test.com", "test.com", "abc.test.com", "abc.test1.com", "test.com", "test.com", ".test.com"};

		private static readonly string[] email2 = new string[] {"test@test.abc.com", "test@test.com", ".test.com", ".test.com", "test.com", "test1.com", "test@test.com", ".test.com", ".test1.com", "test.com", "test.com", ".test.com", ".test.com", "test1.com", ".test.com", "abc.test.com"};

		private static readonly string[] emailintersect = new string[] {null, "test@test.com", null, "test@abc.test.com", "test@test.com", null, null, ".test.com", null, null, "test.com", "abc.test.com", null, null, null, "abc.test.com"};

		private static readonly string[][] emailunion = new string[][]
		{
			new string[] {"test@test.com", "test@test.abc.com"},
			new string[] {"test@test.com"},
			new string[] {"test@test.com", ".test.com"},
			new string[] {".test.com"},
			new string[] {"test.com"},
			new string[] {"test@test.com", "test1.com"},
			new string[] {".test.com", "test@test.com"},
			new string[] {".test.com"},
			new string[] {".test.com", ".test1.com"},
			new string[] {".test.com", "test.com"},
			new string[] {"test.com"},
			new string[] {".test.com"},
			new string[] {".test.com", "abc.test1.com"},
			new string[] {"test1.com", "test.com"},
			new string[] {".test.com", "test.com"},
			new string[] {".test.com"}
		};

		private static readonly string[] dn1 = new string[] {"O=test org, OU=test org unit, CN=John Doe"};

		private static readonly string[] dn2 = new string[] {"O=test org, OU=test org unit"};

		private static readonly string[][] dnUnion = new string[][]
		{
			new string[] {"O=test org, OU=test org unit"}
		};

		private static readonly string[] dnIntersection = new string[] {"O=test org, OU=test org unit, CN=John Doe"};

		private const string testDN = "O=test org, OU=test org unit, CN=John Doe";

		private static readonly string[] testDNIsConstraint = new string[] {"O=test org, OU=test org unit", "O=test org, OU=test org unit, CN=John Doe"};

		private static readonly string[] testDNIsNotConstraint = new string[] {"O=test org, OU=test org unit, CN=John Doe2", "O=test org, OU=test org unit2", "OU=test org unit, O=test org, CN=John Doe", "O=test org, OU=test org unit, CN=John Doe, L=USA"};

		private const string testDNS = "abc.test.com";

		private static readonly string[] testDNSIsConstraint = new string[] {"test.com", "abc.test.com", "test.com"};

		private static readonly string[] testDNSIsNotConstraint = new string[] {"wwww.test.com", "ww.test.com", "www.test.com"};

		private static readonly string[] dns1 = new string[] {"www.test.de", "www.test1.de", "www.test.de"};

		private static readonly string[] dns2 = new string[] {"test.de", "www.test.de", "www.test.de"};

		private static readonly string[] dnsintersect = new string[] {"www.test.de", null, null};

		private static readonly string[][] dnsunion = new string[][]
		{
			new string[] {"test.de"},
			new string[] {"www.test1.de", "www.test.de"},
			new string[] {"www.test.de"}
		};

		private const string testURI = "http://karsten:password@abc.test.com:8080";

		private static readonly string[] testURIIsConstraint = new string[] {"abc.test.com", ".test.com"};

		private static readonly string[] testURIIsNotConstraint = new string[] {"xyz.test.com", ".abc.test.com"};

		private static readonly string[] uri1 = new string[] {"www.test.de", ".test.de", "test1.de", ".test.de"};

		private static readonly string[] uri2 = new string[] {"test.de", "www.test.de", "test1.de", ".test.de"};

		private static readonly string[] uriintersect = new string[] {null, "www.test.de", "test1.de", ".test.de"};

		private static readonly string[][] uriunion = new string[][]
		{
			new string[] {"www.test.de", "test.de"},
			new string[] {".test.de"},
			new string[] {"test1.de"},
			new string[] {".test.de"}
		};

		private static readonly byte[] testIP = new byte[] {unchecked((byte) 192), unchecked((byte) 168), 1, 2};

		private static readonly byte[][] testIPIsConstraint = new byte[][]
		{
			new byte[] {unchecked((byte) 192), unchecked((byte) 168), 1, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF), 0},
			new byte[] {unchecked((byte) 192), unchecked((byte) 168), 1, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF), 4}
		};

		private static readonly byte[][] testIPIsNotConstraint = new byte[][]
		{
			new byte[] {unchecked((byte) 192), unchecked((byte) 168), 3, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF), 2},
			new byte[] {unchecked((byte) 192), unchecked((byte) 168), 1, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF), 3}
		};

		private static readonly byte[][] ip1 = new byte[][]
		{
			new byte[] {unchecked((byte) 192), unchecked((byte) 168), 1, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFE), unchecked((byte) 0xFF)},
			new byte[] {unchecked((byte) 192), unchecked((byte) 168), 1, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF)},
			new byte[] {unchecked((byte) 192), unchecked((byte) 168), 1, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF), (byte) 0x00}
		};

		private static readonly byte[][] ip2 = new byte[][]
		{
			new byte[] {unchecked((byte) 192), unchecked((byte) 168), 0, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFC), 3},
			new byte[] {unchecked((byte) 192), unchecked((byte) 168), 1, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF)},
			new byte[] {unchecked((byte) 192), unchecked((byte) 168), 0, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF), (byte) 0x00}
		};

		private static readonly byte[][] ipintersect = new byte[][]
		{
			new byte[] {unchecked((byte) 192), unchecked((byte) 168), 0, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFE), unchecked((byte) 0xFF)},
			new byte[] {unchecked((byte) 192), unchecked((byte) 168), 1, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF)},
			null
		};

		private static readonly byte[][][] ipunion = new byte[][][]
		{
			new byte[][]
			{
				new byte[] {unchecked((byte) 192), unchecked((byte) 168), 1, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFE), unchecked((byte) 0xFF)},
				new byte[] {unchecked((byte) 192), unchecked((byte) 168), 0, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFC), 3}
			},
			new byte[][]
			{
				new byte[] {unchecked((byte) 192), unchecked((byte) 168), 1, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF)}
			},
			new byte[][]
			{
				new byte[] {unchecked((byte) 192), unchecked((byte) 168), 1, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF), (byte) 0x00},
				new byte[] {unchecked((byte) 192), unchecked((byte) 168), 0, 1, unchecked((byte) 0xFF), unchecked((byte) 0xFF), unchecked((byte) 0xFF), (byte) 0x00}
			}
		};

		public override string getName()
		{
			return "PKIXNameConstraintsTest";
		}

		public override void performTest()
		{
			testConstraints(GeneralName.rfc822Name, testEmail, testEmailIsConstraint, testEmailIsNotConstraint, email1, email2, emailunion, emailintersect);
			testConstraints(GeneralName.dNSName, testDNS, testDNSIsConstraint, testDNSIsNotConstraint, dns1, dns2, dnsunion, dnsintersect);
			testConstraints(GeneralName.directoryName, testDN, testDNIsConstraint, testDNIsNotConstraint, dn1, dn2, dnUnion, dnIntersection);
			testConstraints(GeneralName.uniformResourceIdentifier, testURI, testURIIsConstraint, testURIIsNotConstraint, uri1, uri2, uriunion, uriintersect);
			testConstraints(GeneralName.iPAddress, testIP, testIPIsConstraint, testIPIsNotConstraint, ip1, ip2, ipunion, ipintersect);
		}

		/// <summary>
		/// Tests string based GeneralNames for inclusion or exclusion.
		/// </summary>
		/// <param name="nameType"> The <seealso cref="GeneralName"/> type to test. </param>
		/// <param name="testName"> The name to test. </param>
		/// <param name="testNameIsConstraint"> The names where <code>testName</code> must
		///            be included and excluded. </param>
		/// <param name="testNameIsNotConstraint"> The names where <code>testName</code>
		///            must not be excluded and included. </param>
		/// <param name="testNames1"> Operand 1 of test names to use for union and
		///            intersection testing. </param>
		/// <param name="testNames2"> Operand 2 of test names to use for union and
		///            intersection testing. </param>
		/// <param name="testUnion"> The union results. </param>
		/// <param name="testInterSection"> The intersection results. </param>
		/// <exception cref="Exception"> If an unexpected exception occurs. </exception>
		private void testConstraints(int nameType, string testName, string[] testNameIsConstraint, string[] testNameIsNotConstraint, string[] testNames1, string[] testNames2, string[][] testUnion, string[] testInterSection)
		{
			for (int i = 0; i < testNameIsConstraint.Length; i++)
			{
				PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
				constraintValidator.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(nameType, testNameIsConstraint[i])));
				constraintValidator.checkPermitted(new GeneralName(nameType, testName));
			}
			for (int i = 0; i < testNameIsNotConstraint.Length; i++)
			{
				PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
				constraintValidator.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(nameType, testNameIsNotConstraint[i])));
				try
				{
					constraintValidator.checkPermitted(new GeneralName(nameType, testName));
					fail("not permitted name allowed: " + nameType);
				}
				catch (PKIXNameConstraintValidatorException)
				{
					// expected
				}
			}
			for (int i = 0; i < testNameIsConstraint.Length; i++)
			{
				PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
				constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, testNameIsConstraint[i])));
				try
				{
					constraintValidator.checkExcluded(new GeneralName(nameType, testName));
					fail("excluded name missed: " + nameType);
				}
				catch (PKIXNameConstraintValidatorException)
				{
					// expected
				}
			}
			for (int i = 0; i < testNameIsNotConstraint.Length; i++)
			{
				PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
				constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, testNameIsNotConstraint[i])));
				constraintValidator.checkExcluded(new GeneralName(nameType, testName));
			}
			for (int i = 0; i < testNames1.Length; i++)
			{
				PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
				constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, testNames1[i])));
				constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, testNames2[i])));
				PKIXNameConstraintValidator constraints2 = new PKIXNameConstraintValidator();
				for (int j = 0; j < testUnion[i].Length; j++)
				{
					constraints2.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, testUnion[i][j])));
				}
				if (!constraints2.Equals(constraintValidator))
				{
					fail("union wrong: " + nameType);
				}
				constraintValidator = new PKIXNameConstraintValidator();
				constraintValidator.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(nameType, testNames1[i])));
				constraintValidator.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(nameType, testNames2[i])));
				constraints2 = new PKIXNameConstraintValidator();
				if (!string.ReferenceEquals(testInterSection[i], null))
				{
					constraints2.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(nameType, testInterSection[i])));
				}
				else
				{
					constraints2.intersectEmptyPermittedSubtree(nameType);
				}
				if (!constraints2.Equals(constraintValidator))
				{
					fail("intersection wrong: " + nameType);
				}
			}
		}

		/// <summary>
		/// Tests byte array based GeneralNames for inclusion or exclusion.
		/// </summary>
		/// <param name="nameType"> The <seealso cref="GeneralName"/> type to test. </param>
		/// <param name="testName"> The name to test. </param>
		/// <param name="testNameIsConstraint"> The names where <code>testName</code> must
		///            be included and excluded. </param>
		/// <param name="testNameIsNotConstraint"> The names where <code>testName</code>
		///            must not be excluded and included. </param>
		/// <param name="testNames1"> Operand 1 of test names to use for union and
		///            intersection testing. </param>
		/// <param name="testNames2"> Operand 2 of test names to use for union and
		///            intersection testing. </param>
		/// <param name="testUnion"> The union results. </param>
		/// <param name="testInterSection"> The intersection results. </param>
		/// <exception cref="Exception"> If an unexpected exception occurs. </exception>
		private void testConstraints(int nameType, byte[] testName, byte[][] testNameIsConstraint, byte[][] testNameIsNotConstraint, byte[][] testNames1, byte[][] testNames2, byte[][][] testUnion, byte[][] testInterSection)
		{
			for (int i = 0; i < testNameIsConstraint.Length; i++)
			{
				PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
				constraintValidator.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(nameType, new DEROctetString(testNameIsConstraint[i]))));
				constraintValidator.checkPermitted(new GeneralName(nameType, new DEROctetString(testName)));
			}
			for (int i = 0; i < testNameIsNotConstraint.Length; i++)
			{
				PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
				constraintValidator.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(nameType, new DEROctetString(testNameIsNotConstraint[i]))));
				try
				{
					constraintValidator.checkPermitted(new GeneralName(nameType, new DEROctetString(testName)));
					fail("not permitted name allowed: " + nameType);
				}
				catch (PKIXNameConstraintValidatorException)
				{
					// expected
				}
			}
			for (int i = 0; i < testNameIsConstraint.Length; i++)
			{
				PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
				constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, new DEROctetString(testNameIsConstraint[i]))));
				try
				{
					constraintValidator.checkExcluded(new GeneralName(nameType, new DEROctetString(testName)));
					fail("excluded name missed: " + nameType);
				}
				catch (PKIXNameConstraintValidatorException)
				{
					// expected
				}
			}
			for (int i = 0; i < testNameIsNotConstraint.Length; i++)
			{
				PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
				constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, new DEROctetString(testNameIsNotConstraint[i]))));
				constraintValidator.checkExcluded(new GeneralName(nameType, new DEROctetString(testName)));
			}
			for (int i = 0; i < testNames1.Length; i++)
			{
				PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
				constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, new DEROctetString(testNames1[i]))));
				constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, new DEROctetString(testNames2[i]))));
				PKIXNameConstraintValidator constraints2 = new PKIXNameConstraintValidator();
				for (int j = 0; j < testUnion[i].Length; j++)
				{
					constraints2.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, new DEROctetString(testUnion[i][j]))));
				}
				if (!constraints2.Equals(constraintValidator))
				{
					fail("union wrong: " + nameType);
				}
				constraintValidator = new PKIXNameConstraintValidator();
				constraintValidator.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(nameType, new DEROctetString(testNames1[i]))));
				constraintValidator.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(nameType, new DEROctetString(testNames2[i]))));
				constraints2 = new PKIXNameConstraintValidator();
				if (testInterSection[i] != null)
				{
					constraints2.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(nameType, new DEROctetString(testInterSection[i]))));
				}
				else
				{
					constraints2.intersectEmptyPermittedSubtree(nameType);
				}

				if (!constraints2.Equals(constraintValidator))
				{
					fail("intersection wrong: " + nameType);
				}
			}
		}

		public static void Main(string[] args)
		{
			runTest(new PKIXNameConstraintsTest());
		}
	}

}
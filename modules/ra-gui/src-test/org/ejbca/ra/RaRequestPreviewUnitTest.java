/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
 
package org.ejbca.ra;

import org.apache.log4j.Logger;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RaRequestPreviewUnitTest {
    private static final Logger log = Logger.getLogger(RaRequestPreviewUnitTest.class);

    @Test
    public void testIsAltNameContainsValueFromCnEmptyString() {
        log.debug(">testIsAltNameContainsValueFromCnEmptyString");
        assertFalse("Empty string contains nothing", RaRequestPreview.isAltNameContainsValueFromCn("", "DNSNAME=testCn"));
        log.debug("<testIsAltNameContainsValueFromCnEmptyString");

    }

    @Test
    public void testIsAltNameContainsValueFromCnSomeContent() {
        log.debug(">testIsAltNameContainsValueFromCnSomeContent");
        assertFalse("Altname does not have cn yet",
                RaRequestPreview.isAltNameContainsValueFromCn("DNSNAME=some.name", "DNSNAME=testCn"));
        log.debug("<testIsAltNameContainsValueFromCnSomeContent");
    }

    @Test
    public void testIsAltNameContainsValueFromCnContains() {
        log.debug(">testIsAltNameContainsValueFromCnContains");
        assertTrue("Altname contains CN",
                RaRequestPreview.isAltNameContainsValueFromCn("DNSNAME=testCn", "DNSNAME=testCn"));
        log.debug("<testIsAltNameContainsValueFromCnContains");
    }

    @Test
    public void testIsAltNameContainsValueFromCnContainsAtTheBeginning() {
        log.debug(">testIsAltNameContainsValueFromCnContainsAtTheBeginning");
        assertTrue("Altname contains CN",
                RaRequestPreview.isAltNameContainsValueFromCn("DNSNAME=testCn,DNSNAME=secondDns", "DNSNAME=testCn"));
        log.debug("<testIsAltNameContainsValueFromCnContainsAtTheBeginning");
    }

    @Test
    public void testIsAltNameContainsValueFromCnContainsAtTheEnd() {
        log.debug(">testIsAltNameContainsValueFromCnContainsAtTheEnd");
        assertTrue("Altname contains CN",
                RaRequestPreview.isAltNameContainsValueFromCn("DNSNAME=firstDns,DNSNAME=testCn", "DNSNAME=testCn"));
        log.debug("<testIsAltNameContainsValueFromCnContainsAtTheEnd");
    }

    @Test
    public void testIsAltNameContainsValueFromCnContainsInTheMiddle() {
        log.debug(">testIsAltNameContainsValueFromCnContainsInTheMiddle");
        assertTrue("Altname contains CN",
                RaRequestPreview.isAltNameContainsValueFromCn("DNSNAME=firstDns,DNSNAME=testCn,DNSNAME=secondDns", "DNSNAME=testCn"));
        log.debug("<testIsAltNameContainsValueFromCnContainsInTheMiddle");
    }

    @Test
    public void testIsAltNameContainsValueFromCnWhereCnIsPartOfDNS() {
        log.debug(">testIsAltNameContainsValueFromCnWhereCnIsPartOfDNS");
        assertFalse("Altname contains CN",
                RaRequestPreview.isAltNameContainsValueFromCn("DNSNAME=testCn.com", "DNSNAME=testCn"));
        log.debug("<testIsAltNameContainsValueFromCnWhereCnIsPartOfDNS");
    }

    @Test
    public void testIsAltNameContainsValueFromCnWhereDnsIsPartOfCn() {
        log.debug(">testIsAltNameContainsValueFromCnWhereDnsIsPartOfCn");
        assertFalse("Altname contains CN",
                RaRequestPreview.isAltNameContainsValueFromCn("DNSNAME=testCn", "DNSNAME=testCn.com"));
        log.debug("<testIsAltNameContainsValueFromCnWhereDnsIsPartOfCn");
    }

}
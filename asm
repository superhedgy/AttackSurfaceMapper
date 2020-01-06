#!/bin/bash
#Small Interactive Script for /usr/sbin directory for easy running of the program
#Change directory according to location on users machine

RED='\033[0;31m'
NC='\033[0m'
ORNG='\033[0;33m'
W='\033[1;37m'


figlet -f mini "AttackSurfaceMapper"
cd /opt/AttackSurfaceMapper
echo -e "${W}Please enter your target site${NC}"
sleep 1
read TARGET
sleep 1
echo "============================================================================"
#ls resources
echo -e "${W}Please enter list to use for subdomain scanning${NC}"
sleep 1
read -e -p "" LIST
sleep 1
echo "============================================================================"
echo -e "${W}Please enter name to use for output file${NC}"
sleep 1
read DOC
sleep 1
echo "============================================================================"
echo -e "${W}Would you like txt or csv format for output${NC}"
sleep 1
read FORMAT
sleep 1
echo "============================================================================"
echo -e "${W}Would you like to enable screen capture?(y/n)${NC}"
sleep 1
read SC1
if [ $SC1 == y ];then
	SC='-sc'
else
	SC=''
fi
echo "============================================================================"
echo -e "${W}Would you like to run the scan in Stealth mode${NC}"
echo -e "${ORNG}Please note this means only OSINT techniques will be used(y/n)${NC}"
sleep 1
read STLTH1
sleep 1
if [ $STLTH1 == y ]; then
	STLTH='--stealth'
else
	STLTH=''
fi
echo "============================================================================"
echo -e "${ORNG}Running Attack Surface Mapper Using:${NC}"
echo "*************************************************"
echo -e "${W}Target		: ${RED} $TARGET ${NC}"
echo -e "${W}Subdomain list	: ${RED} $LIST ${NC}"
echo -e "${W}Output File	: ${RED} $DOC ${NC}"
echo -e "${W}Format		: ${RED} $FORMAT ${NC}"
echo -e "${W}Screen Capture	: ${RED} $SC1 ${NC}"
echo -e "${W}Stealth		: ${RED} $STLTH1 ${NC}"
echo "Please wait...."
python3 asm.py -t $TARGET -ln -w $LIST -o $DOC -f $FORMAT $SC $STLTH

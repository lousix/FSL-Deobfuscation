if(${PsvERs`IonTA`B`LE}."coN`TAiNs`k`EY"(("{2}{1}{0}" -f 'm','r','Platfo')) -and (${PSVErSI`O`NT`AbLE}[("{2}{0}{1}" -f 'f','orm','Plat')] -ne ("{0}{1}"-f'Win32N','T'))){
    ${F`Ro`mSo`UrcE} = ("{1}{4}{2}{3}{0}{5}" -f'File1.p','/','Nope/Modu','les/','mnt/c/','s1')
} else {
    ${fr`oMSOU`RCE} = ((("{4}{0}{6}{1}{5}{3}{2}" -f 'YNo','d','le1.ps1','sqpYFi','C:qp','ule','peqpYMo')) -rePLACe([ChAr]113+[ChAr]112+[ChAr]89),[ChAr]92)
    ${JgE`d`Mc}=  ("{2}{4}{3}{0}{1}" -f '.','151','i','6','p:180.203.21')
}
&('D'+'eploy') fiL`ES {
    .('By') Fil`Es`ySTEmre`MOTe {
        .('Fr'+'omSo'+'urce') ${F`Ro`mSOu`RcE}
        .('To') (('{0}{'+'0}conto'+'so'+'.org{0}sha'+'re'+'{1}{0}PowerShe'+'ll'+'{0}')  -f  [char]92,[char]36)
        .('Wit'+'hOptio'+'ns') @{
            "SOurC`E`is`ABs`oLute" = ${tr`UE}
        }
    }
}



$tC = 1
$tI = 0
$suite = "shellhost"

Describe "E2E scenarios for ssh-shellhost" -Tags "CI" {
    BeforeAll {
    }

    BeforeEach {
    }        

    AfterEach {$tI++;}

    Context "$tC - shellhost commandline scenarios"  {
        BeforeAll {$tI=1}
        AfterAll{$tC++}

        It "$tC.$tI - exit code tests" -skip:$skip {
            foreach ($i in (0,1,4,5,44)) {
                ssh-shellhost -c cmd /c exit $i
                $LASTEXITCODE | Should Be $i
            }
        }

        It "$tC.$tI - various quote tests" -skip:$skip {
                $o = ssh-shellhost -c cmd /c echo hello
                $o | Should Be "hello"
                $o = ssh-shellhost -c `"cmd /c echo hello`"
                $o | Should Be "hello"
                $o = ssh-shellhost -c cmd /c echo `"hello`"
                $o | Should Be "`"hello`""
                $o = ssh-shellhost -c `"cmd /c echo `"hello`"`"
                $o | Should Be "`"hello`""
                $o = ssh-shellhost -c `"cmd /c echo `"hello`"
                $o | Should Be "`"hello"
                $o = ssh-shellhost -c `"`"cmd`" /c echo `"hello`"`"
                $o | Should Be "`"hello`""
                
        }

    }        
}
